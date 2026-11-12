import CryptoKit
import CommonCrypto
import Foundation
import JavaScriptCore

public struct RuleExecutionContext: Sendable {
    public var variables: [String: String]
    public var baseURL: String
    public var key: String?
    public var page: Int?
    public var source: BookSource?
    public var book: Book?
    public var chapter: BookChapter?
    public var isHTMLFragment: Bool
    public var content: JSONValue?

    public init(
        variables: [String: String] = [:],
        baseURL: String = "",
        key: String? = nil,
        page: Int? = nil,
        source: BookSource? = nil,
        book: Book? = nil,
        chapter: BookChapter? = nil,
        isHTMLFragment: Bool = false,
        content: JSONValue? = nil
    ) {
        self.variables = variables
        self.baseURL = baseURL
        self.key = key
        self.page = page
        self.source = source
        self.book = book
        self.chapter = chapter
        self.isHTMLFragment = isHTMLFragment
        self.content = content
    }
}

public struct JavaScriptRuleResult: Sendable {
    public var value: JSONValue
    public var variables: [String: String]
}

/// JavaScript's synchronous network bridges can block. Keep those calls off
/// Swift's cooperative executor and off shared actors such as the cookie policy.
enum RuleExecutionWorker {
    static func run<Value: Sendable>(_ operation: @escaping @Sendable () throws -> Value) async throws -> Value {
        try Task.checkCancellation()
        let result = try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result { try operation() })
            }
        }
        try Task.checkCancellation()
        return result
    }
}

public protocol JavaScriptNetworkLoading: Sendable {
    func load(_ request: URLRequest) throws -> HTTPResponse
}

public protocol JavaScriptRedirectNetworkLoading: JavaScriptNetworkLoading {
    func load(_ request: URLRequest, followRedirects: Bool) throws -> HTTPResponse
}

public final class SynchronousJavaScriptNetworkLoader: JavaScriptRedirectNetworkLoading, @unchecked Sendable {
    public init() {}

    public func load(_ request: URLRequest) throws -> HTTPResponse {
        try load(request, followRedirects: true)
    }

    public func load(_ original: URLRequest, followRedirects: Bool) throws -> HTTPResponse {
        let settings = ApplicationSettingsStore.shared.settings
        let request = settings.configure(original)
        let address = try ApplicationSettings.parseHosts(settings.hosts)[request.url?.host?.lowercased() ?? ""]
        if followRedirects || (settings.proxy.isEmpty && address != nil) {
            let semaphore = DispatchSemaphore(value: 0)
            let lock = NSLock()
            nonisolated(unsafe) var result: Result<HTTPResponse, Error>?
            // The synchronous JS caller waits for this request. Detached tasks
            // otherwise default to medium priority and cause priority inversion
            // during interactive search/source switching.
            let task = Task.detached(priority: Task.currentPriority) {
                let value: Result<HTTPResponse, Error>
                do {
                    let response: HTTPResponse
                    if followRedirects { response = try await URLSessionHTTPTransport.shared.data(for: request) }
                    else { response = try await HostsHTTPTransport.data(for: request, address: address!, ignoreCertificateErrors: settings.ignoreCertificateErrors) }
                    value = .success(response)
                } catch HTTPClientError.statusResponse(let response) { value = .success(response) }
                catch { value = .failure(error) }
                lock.withLock { result = value }
                semaphore.signal()
            }
            guard semaphore.wait(timeout: .now() + max(1, request.timeoutInterval) + 1) == .success else {
                task.cancel()
                throw URLError(.timedOut)
            }
            lock.lock(); let value = result; lock.unlock()
            return try value?.get() ?? { throw HTTPClientError.nonHTTPResponse }()
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .always
        configuration.httpShouldSetCookies = true
        configuration.httpCookieStorage = .shared
        try settings.configure(configuration)
        let delegate: any URLSessionDelegate = followRedirects ? LegadoUnsafeTrustDelegate.shared : JavaScriptRedirectBlocker()
        let callbackQueue = OperationQueue()
        callbackQueue.qualityOfService = Thread.current.qualityOfService
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: callbackQueue)
        defer { session.finishTasksAndInvalidate() }
        let started = Date()
        do {
            let response = try load(request, session: session)
            DiagnosticLog.shared.network(request, status: response.statusCode, startedAt: started)
            return response
        } catch {
            DiagnosticLog.shared.network(request, error: error, startedAt: started)
            throw error
        }
    }

    private func load(_ request: URLRequest, session: URLSession) throws -> HTTPResponse {
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        nonisolated(unsafe) var output: Result<HTTPResponse, Error>?
        let task = session.dataTask(with: request) { data, response, error in
            let result: Result<HTTPResponse, Error>
            if let error {
                result = .failure(error)
            } else if let http = response as? HTTPURLResponse, let url = http.url {
                result = .success(.init(
                    data: data ?? Data(),
                    statusCode: http.statusCode,
                    headers: http.allHeaderFields.reduce(into: [:]) { values, entry in
                        values[String(describing: entry.key)] = String(describing: entry.value)
                    },
                    finalURL: url
                ))
            } else {
                result = .failure(HTTPClientError.nonHTTPResponse)
            }
            lock.lock()
            output = result
            lock.unlock()
            semaphore.signal()
        }
        task.resume()
        let timeout = min(max(request.timeoutInterval, 1), 180)
        guard semaphore.wait(timeout: .now() + timeout + 1) == .success else {
            task.cancel()
            throw URLError(.timedOut)
        }
        lock.lock()
        let result = output
        lock.unlock()
        return try result?.get() ?? { throw HTTPClientError.nonHTTPResponse }()
    }
}

private final class JavaScriptRedirectBlocker: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        LegadoUnsafeTrustDelegate.resolution(for: challenge)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

public struct JavaScriptRuleEvaluator: Sendable {
    public var maximumScriptLength: Int
    public var maximumResultLength: Int
    private let networkLoader: any JavaScriptNetworkLoading
    private let urlBuilder: LegadoURLBuilder

    public func evaluateAsync(script: String, result: JSONValue, executionContext: RuleExecutionContext) async throws -> JavaScriptRuleResult {
        try await RuleExecutionWorker.run {
            try evaluate(script: script, result: result, executionContext: executionContext)
        }
    }

    public init(
        // published sources' jsLib reach 150 KB
        maximumScriptLength: Int = 1_024 * 1_024,
        maximumResultLength: Int = 2 * 1_024 * 1_024,
        networkLoader: any JavaScriptNetworkLoading = SynchronousJavaScriptNetworkLoader(),
        urlBuilder: LegadoURLBuilder = .init()
    ) {
        self.maximumScriptLength = maximumScriptLength
        self.maximumResultLength = maximumResultLength
        self.networkLoader = networkLoader
        self.urlBuilder = urlBuilder
    }

    public func evaluate(
        script: String,
        result: JSONValue,
        executionContext: RuleExecutionContext
    ) throws -> JavaScriptRuleResult {
        try evaluate(script: script, result: result, executionContext: executionContext,
                     virtualMachine: JSVirtualMachine(), stringifyResult: false)
    }

    /// A rule shares java.get/put storage, but each match gets fresh JS globals.
    /// Keep this closure on the synchronous replacement call's thread.
    func replacementEvaluator(script: String, book: Book, chapter: BookChapter) -> (String) throws -> String {
        var virtualMachine: JSVirtualMachine?
        var executionContext = RuleExecutionContext(book: book, chapter: chapter)
        return { match in
            if virtualMachine == nil { virtualMachine = JSVirtualMachine() }
            let result = try autoreleasepool {
                try evaluate(script: script, result: .string(match), executionContext: executionContext,
                             virtualMachine: virtualMachine!, stringifyResult: true)
            }
            executionContext.variables = result.variables
            return result.value.stringValue
        }
    }

    private func evaluate(
        script: String,
        result: JSONValue,
        executionContext: RuleExecutionContext,
        virtualMachine: JSVirtualMachine,
        stringifyResult: Bool
    ) throws -> JavaScriptRuleResult {
        guard script.utf8.count <= maximumScriptLength else {
            throw RuleEngineError.resourceLimit(rule: script, detail: "JavaScript 规则超过长度上限")
        }
        try rejectUnboundedExecution(script)

        let box = JSVariableBox(executionContext.variables)
        guard let context = JSContext(virtualMachine: virtualMachine) else {
            throw RuleEngineError.invalidInput(rule: script, expected: "无法创建 JavaScriptCore 上下文")
        }
        var exceptionMessage: String?
        context.exceptionHandler = { _, exception in
            exceptionMessage = exception?.toString() ?? "未知 JavaScript 异常"
            DiagnosticLog.shared.record(.error, category: "JS", message: exceptionMessage ?? "未知 JavaScript 异常")
        }
        context.setObject(result.foundationObject, forKeyedSubscript: "result" as NSString)
        context.setObject((executionContext.content ?? result).foundationObject, forKeyedSubscript: "src" as NSString)
        context.setObject(result.foundationObject, forKeyedSubscript: "$" as NSString)
        context.setObject(executionContext.baseURL, forKeyedSubscript: "baseUrl" as NSString)
        context.setObject(executionContext.key ?? "", forKeyedSubscript: "key" as NSString)
        context.setObject(executionContext.page ?? 0, forKeyedSubscript: "page" as NSString)
        installJava(in: context, variables: box, result: result, executionContext: executionContext)
        installCookie(in: context)
        installAndroidClasses(in: context)
        installJavaImporterCompatibility(in: context)
        installSource(in: context, source: executionContext.source, variables: box)
        installBook(in: context, book: executionContext.book)
        installChapter(in: context, chapter: executionContext.chapter)
        installAndroidAPIs(in: context, result: result, executionContext: executionContext)
        context.evaluateScript("""
            (function () {
              var nativeParse = JSON.parse;
              JSON.parse = function (value) {
                if (typeof value !== 'string') return value;
                var text = value;
                if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
                text = text.trim();
                if (!text || '[{"-0123456789tfn'.indexOf(text.charAt(0)) < 0) return value;
                return nativeParse(text);
              };
            })();
            """)

        if let library = executionContext.source?.jsLib?.trimmingCharacters(in: .whitespacesAndNewlines),
           !library.isEmpty {
            guard library.utf8.count <= maximumScriptLength else {
                throw RuleEngineError.resourceLimit(rule: library, detail: "书源 jsLib 超过长度上限")
            }
            try rejectUnboundedExecution(library)
            context.evaluateScript(library)
            if let exceptionMessage {
                throw RuleEngineError.malformedRule(rule: library, detail: "书源 jsLib 执行失败：\(exceptionMessage)")
            }
        }

        let evaluated = context.evaluateScript(script)
        if let exceptionMessage {
            throw RuleEngineError.malformedRule(rule: script, detail: "JavaScript 执行失败：\(exceptionMessage)")
        }
        // JavaString supplies getBytes() on a boxed JS String. JSC otherwise
        // bridges it as {"0":"第", "1":"一", ...}, corrupting decrypted text.
        let normalized = evaluated.flatMap {
            context.objectForKeyedSubscript("__legadoUnboxString")?.call(withArguments: [$0])
        }
        let value: JSONValue
        if stringifyResult {
            // Rhino unwraps undefined to null before RegexExtensions.kt calls
            // toString(). Preserve strings directly, rather than JSON encoding.
            if let evaluated, !evaluated.isUndefined, !evaluated.isNull {
                let text = evaluated.toString() ?? "null"
                if evaluated.isNumber {
                    // The reference runs Rhino in interpreted mode, yielding JVM Doubles.
                    let number = evaluated.toDouble()
                    value = .string(number.isFinite ? String(number) : text)
                } else {
                    value = .string(text)
                }
            } else {
                value = .string("null")
            }
        } else {
            value = JSONValue.bridge(normalized?.toObject())
        }
        if let exceptionMessage {
            throw RuleEngineError.malformedRule(rule: script, detail: "JavaScript 执行失败：\(exceptionMessage)")
        }
        guard value.stringValue.utf8.count <= maximumResultLength else {
            throw RuleEngineError.resourceLimit(rule: script, detail: "JavaScript 结果超过长度上限")
        }
        return .init(value: value, variables: box.values)
    }

    private func installJava(
        in context: JSContext,
        variables: AnyObject,
        result: JSONValue,
        executionContext: RuleExecutionContext
    ) {
        guard let box = variables as? VariableBoxProxy else { return }
        installJavaBlocks(
            in: context,
            get: { key in
                if key == "bookName", let book = executionContext.book { return book.name }
                if key == "title", let chapter = executionContext.chapter { return chapter.title }
                return box.get(key)
            },
            put: { box.put($0, $1) },
            result: result,
            executionContext: executionContext
        )
    }

    private func installCookie(in context: JSContext) {
        let object = JSValue(newObjectIn: context)
        let getCookie: @convention(block) (String) -> String = {
            LegadoCookieStore.shared.cookieHeader(for: $0)
        }
        let getKey: @convention(block) (String, String) -> String = {
            LegadoCookieStore.shared.cookie(for: $0, key: $1)
        }
        let setCookie: @convention(block) (String, String?) -> Void = { url, value in
            LegadoCookieStore.shared.setCookie(value ?? "", for: url)
        }
        let removeCookie: @convention(block) (String) -> Void = {
            LegadoCookieStore.shared.removeCookies(for: $0)
        }
        object?.setObject(getCookie, forKeyedSubscript: "getCookie" as NSString)
        object?.setObject(getKey, forKeyedSubscript: "getKey" as NSString)
        object?.setObject(setCookie, forKeyedSubscript: "setCookie" as NSString)
        object?.setObject(setCookie, forKeyedSubscript: "replaceCookie" as NSString)
        object?.setObject(setCookie, forKeyedSubscript: "setWebCookie" as NSString)
        object?.setObject(removeCookie, forKeyedSubscript: "removeCookie" as NSString)
        context.setObject(object, forKeyedSubscript: "cookie" as NSString)
        context.evaluateScript("""
            (function () {
              cookie.cookieToMap = function (header) {
                var map = {};
                String(header || '').split(';').forEach(function (part) {
                  var separator = part.indexOf('=');
                  if (separator <= 0) return;
                  var key = part.slice(0, separator).trim();
                  var value = part.slice(separator + 1).trim();
                  if (value || value === 'null') map[key] = value;
                });
                return map;
              };
              cookie.mapToCookie = function (map) {
                if (!map) return null;
                var values = [];
                for (var key in map) {
                  if (Object.prototype.hasOwnProperty.call(map, key)) {
                    values.push(key + '=' + map[key]);
                  }
                }
                return values.length ? values.join('; ') : null;
              };
            })();
            """)
    }

    private func installJavaImporterCompatibility(in context: JSContext) {
        let utf8Bytes: @convention(block) (String) -> [Int] = { value in
            Data(value.utf8).map { Int(Int8(bitPattern: $0)) }
        }
        let utf8String: @convention(block) (Any?) -> String = { value in
            String(decoding: Self.byteData(from: value), as: UTF8.self)
        }
        let maximumBytes = maximumResultLength
        let aesCBC: @convention(block) (Int, Any?, Any?, Any?) -> [Int]? = { operation, keyValue, ivValue, dataValue in
            let key = Self.byteData(from: keyValue)
            let iv = Self.byteData(from: ivValue)
            let input = Self.byteData(from: dataValue)
            guard [1, 2].contains(operation), [16, 24, 32].contains(key.count),
                  iv.count == kCCBlockSizeAES128, input.count <= maximumBytes else { return nil }
            var output = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
            let capacity = output.count
            var written = 0
            let status = key.withUnsafeBytes { keyBytes in
                iv.withUnsafeBytes { ivBytes in
                    input.withUnsafeBytes { inputBytes in
                        CCCrypt(operation == 1 ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt),
                                CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                                keyBytes.baseAddress, key.count, ivBytes.baseAddress,
                                inputBytes.baseAddress, input.count, &output, capacity, &written)
                    }
                }
            }
            guard status == kCCSuccess else { return nil }
            return output.prefix(written).map { Int(Int8(bitPattern: $0)) }
        }
        let base64EncodeBytes: @convention(block) (Any?) -> String = { value in
            Self.byteData(from: value).base64EncodedString()
        }
        let base64DecodeBytes: @convention(block) (String) -> [Int] = { value in
            guard let data = Data(base64Encoded: value) else { return [] }
            return data.map { Int(Int8(bitPattern: $0)) }
        }
        let hexEncodeBytes: @convention(block) (Any?) -> String = { value in
            Self.byteData(from: value).map { String(format: "%02X", $0) }.joined()
        }
        let hmacSHA1: @convention(block) (Any?, Any?) -> [Int] = { keyValue, dataValue in
            let key = SymmetricKey(data: Self.byteData(from: keyValue))
            let authentication = HMAC<Insecure.SHA1>.authenticationCode(
                for: Self.byteData(from: dataValue),
                using: key
            )
            return authentication.map { Int(Int8(bitPattern: $0)) }
        }
        let formURLEncode: @convention(block) (String) -> String = { Self.formURLEncode($0) }
        context.setObject(utf8Bytes, forKeyedSubscript: "__legadoUTF8Bytes" as NSString)
        context.setObject(utf8String, forKeyedSubscript: "__legadoUTF8String" as NSString)
        context.setObject(aesCBC, forKeyedSubscript: "__legadoAESCBC" as NSString)
        context.setObject(base64EncodeBytes, forKeyedSubscript: "__legadoBase64EncodeBytes" as NSString)
        context.setObject(base64DecodeBytes, forKeyedSubscript: "__legadoBase64DecodeBytes" as NSString)
        context.setObject(hexEncodeBytes, forKeyedSubscript: "__legadoHexEncodeBytes" as NSString)
        context.setObject(hmacSHA1, forKeyedSubscript: "__legadoHmacSHA1" as NSString)
        context.setObject(formURLEncode, forKeyedSubscript: "__legadoFormURLEncode" as NSString)
        context.evaluateScript(Self.javaImporterBootstrap)
    }

    private func installJavaBlocks(
        in context: JSContext,
        get: @escaping (String) -> String,
        put: @escaping (String, String) -> String,
        result: JSONValue,
        executionContext: RuleExecutionContext
    ) {
        let java = JSValue(newObjectIn: context)
        let getBlock: @convention(block) (String) -> String = { key in get(key) }
        let putBlock: @convention(block) (String, Any?) -> String = { key, value in
            put(key, Self.stringify(value))
        }
        let putVolumeBlock: @convention(block) (Any?) -> String = { value in
            let title = Self.stringify(value)
            var volumes = (try? JSONDecoder().decode([String].self, from: Data(get("__legadoVolumes").utf8))) ?? []
            volumes.append(title)
            if let data = try? JSONEncoder().encode(volumes) {
                _ = put("__legadoVolumes", String(decoding: data, as: UTF8.self))
            }
            return title
        }
        let getStringBlock: @convention(block) (String, Any?, Bool) -> String = { rule, content, isURL in
            let input = content.map(JSONValue.bridge) ?? executionContext.content ?? result
            return (try? self.evaluateStringRule(
                rule,
                content: input,
                isURL: isURL,
                executionContext: executionContext
            )) ?? ""
        }
        let md5Block: @convention(block) (String) -> String = { value in
            Insecure.MD5.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
        }
        let base64Encode: @convention(block) (String) -> String = { Data($0.utf8).base64EncodedString() }
        let base64Decode: @convention(block) (String) -> String = {
            Data(base64Encoded: $0).map { String(decoding: $0, as: UTF8.self) } ?? ""
        }
        let base64DecodeToByteArray: @convention(block) (String) -> [Int] = {
            guard let data = Data(base64Encoded: $0) else { return [] }
            return data.map { Int(Int8(bitPattern: $0)) }
        }
        let strToBytes: @convention(block) (String) -> [Int] = {
            Array($0.utf8).map { Int(Int8(bitPattern: $0)) }
        }
        let bytesToStr: @convention(block) (Any?) -> String = { value in
            guard let values = value as? [Any] else { return "" }
            let bytes = values.compactMap { item -> UInt8? in
                if let number = item as? NSNumber { return UInt8(truncatingIfNeeded: number.intValue) }
                if let number = Int(Self.stringify(item)) { return UInt8(truncatingIfNeeded: number) }
                return nil
            }
            return String(decoding: bytes, as: UTF8.self)
        }
        let hexDecodeToByteArray: @convention(block) (String) -> [Int] = { value in
            Self.hexBytes(value).map { Int(Int8(bitPattern: $0)) }
        }
        let hexDecodeToString: @convention(block) (String) -> String = { value in
            String(decoding: Self.hexBytes(value), as: UTF8.self)
        }
        let hexEncodeToString: @convention(block) (String) -> String = { value in
            Data(value.utf8).map { String(format: "%02x", $0) }.joined()
        }
        let timeFormatUTC: @convention(block) (Double, String, Int) -> String = { milliseconds, format, offset in
            let formatter = DateFormatter()
            formatter.locale = Locale.current
            formatter.timeZone = TimeZone(secondsFromGMT: offset / 1_000)
            formatter.dateFormat = format
            return formatter.string(from: Date(timeIntervalSince1970: milliseconds / 1_000))
        }
        let timeFormat: @convention(block) (Double) -> String = { milliseconds in
            let formatter = DateFormatter()
            formatter.locale = Locale.current
            formatter.dateFormat = "yyyy/MM/dd HH:mm"
            return formatter.string(from: Date(timeIntervalSince1970: milliseconds / 1_000))
        }
        let randomUUID: @convention(block) () -> String = { UUID().uuidString }
        let deviceID: @convention(block) () -> String = {
            let key = "ios.installation.identifier"
            let stored = BookSourceRuntimeStore.shared.get(sourceID: "__app__", key: key)
            if !stored.isEmpty { return stored }
            let value = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            BookSourceRuntimeStore.shared.put(sourceID: "__app__", key: key, value: value)
            return value
        }
        let getTag: @convention(block) () -> String = { executionContext.source?.id ?? "" }
        let logValue: @convention(block) (Any?) -> Any? = { value in
            DiagnosticLog.shared.record(category: "JS", message: String(describing: value ?? "null"))
            return value
        }
        context.setObject(logValue, forKeyedSubscript: "__legadoLog" as NSString)
        context.evaluateScript("var console = { log: function() { __legadoLog(Array.prototype.join.call(arguments, ' ')); }, warn: function() { __legadoLog(Array.prototype.join.call(arguments, ' ')); }, error: function() { __legadoLog(Array.prototype.join.call(arguments, ' ')); } };")
        let urlEncode: @convention(block) (String) -> String = {
            Self.formURLEncode($0)
        }
        let getCookieHeader: @convention(block) (String) -> String = {
            LegadoCookieStore.shared.cookieHeader(for: $0)
        }
        let getCookieValue: @convention(block) (String, String) -> String = {
            LegadoCookieStore.shared.cookie(for: $0, key: $1)
        }
        let setCookie: @convention(block) (String, String) -> Void = {
            LegadoCookieStore.shared.setCookie($1, for: $0)
        }
        let ajax: @convention(block) (Any?, Any?) -> String = { value, timeoutValue in
            let rawURL = Self.firstURL(value)
            do {
                let response = try self.loadJavaScriptRequest(
                    rawURL,
                    extraHeaders: [:],
                    timeoutValue: timeoutValue,
                    executionContext: executionContext
                )
                return response.decodedText
            } catch {
                return error.localizedDescription
            }
        }
        let ajaxAll: @convention(block) (Any?, Any?) -> [[String: Any]] = { value, _ in
            let urls: [String]
            if let values = value as? [Any] {
                urls = values.map(Self.stringify)
            } else {
                urls = [Self.stringify(value)]
            }
            return urls.map { rawURL in
                do {
                    let response = try self.loadJavaScriptRequest(
                        rawURL,
                        extraHeaders: [:],
                        timeoutValue: nil,
                        executionContext: executionContext
                    )
                    return [
                        "url": response.finalURL.absoluteString,
                        "body": response.decodedText,
                        "code": response.statusCode,
                        "headers": response.headers
                    ]
                } catch {
                    return [
                        "url": rawURL,
                        "body": error.localizedDescription,
                        "code": 0,
                        "headers": [:]
                    ]
                }
            }
        }
        let directRequest: @convention(block) (String, String, Any?, Any?, Any?) -> [String: Any] = {
            method, rawURL, body, headers, timeout in
            do {
                let response = try self.loadDirectJavaScriptRequest(
                    method: method,
                    rawURL: rawURL,
                    body: body.map { Self.stringify($0) },
                    headers: Self.headerMap(headers),
                    timeoutValue: timeout,
                    executionContext: executionContext
                )
                return [
                    "urlText": response.finalURL.absoluteString,
                    "bodyText": response.decodedText,
                    "code": response.statusCode,
                    "headers": response.headers
                ]
            } catch {
                return ["error": error.localizedDescription]
            }
        }
        let connect: @convention(block) (Any?, Any?, Any?) -> [String: Any] = { value, headerValue, timeoutValue in
            let rawURL = Self.firstURL(value)
            do {
                let response = try self.loadJavaScriptRequest(
                    rawURL,
                    extraHeaders: Self.headerMap(headerValue),
                    timeoutValue: timeoutValue,
                    executionContext: executionContext
                )
                return [
                    "url": response.finalURL.absoluteString,
                    "body": response.decodedText,
                    "code": response.statusCode,
                    "message": HTTPURLResponse.localizedString(forStatusCode: response.statusCode),
                    "headers": response.headers,
                    "successful": (200 ... 299).contains(response.statusCode),
                    "callTime": 0
                ]
            } catch {
                return [
                    "url": rawURL,
                    "body": error.localizedDescription,
                    "code": 0,
                    "message": error.localizedDescription,
                    "headers": [:],
                    "successful": false,
                    "callTime": 0
                ]
            }
        }
        java?.setObject(getBlock, forKeyedSubscript: "get" as NSString)
        java?.setObject(putBlock, forKeyedSubscript: "put" as NSString)
        java?.setObject(putVolumeBlock, forKeyedSubscript: "putVolume" as NSString)
        java?.setObject(getStringBlock, forKeyedSubscript: "__getString" as NSString)
        java?.setObject(md5Block, forKeyedSubscript: "md5Encode" as NSString)
        java?.setObject(base64Encode, forKeyedSubscript: "base64Encode" as NSString)
        java?.setObject(base64Decode, forKeyedSubscript: "base64Decode" as NSString)
        java?.setObject(base64DecodeToByteArray, forKeyedSubscript: "base64DecodeToByteArray" as NSString)
        java?.setObject(strToBytes, forKeyedSubscript: "strToBytes" as NSString)
        java?.setObject(bytesToStr, forKeyedSubscript: "bytesToStr" as NSString)
        java?.setObject(hexDecodeToByteArray, forKeyedSubscript: "hexDecodeToByteArray" as NSString)
        java?.setObject(hexDecodeToString, forKeyedSubscript: "hexDecodeToString" as NSString)
        java?.setObject(hexEncodeToString, forKeyedSubscript: "hexEncodeToString" as NSString)
        java?.setObject(timeFormatUTC, forKeyedSubscript: "timeFormatUTC" as NSString)
        java?.setObject(timeFormat, forKeyedSubscript: "timeFormat" as NSString)
        java?.setObject(randomUUID, forKeyedSubscript: "randomUUID" as NSString)
        java?.setObject(deviceID, forKeyedSubscript: "androidId" as NSString)
        java?.setObject(getTag, forKeyedSubscript: "getTag" as NSString)
        java?.setObject(logValue, forKeyedSubscript: "log" as NSString)
        java?.setObject(logValue, forKeyedSubscript: "logType" as NSString)
        java?.setObject(logValue, forKeyedSubscript: "toast" as NSString)
        java?.setObject(urlEncode, forKeyedSubscript: "encodeURI" as NSString)
        java?.setObject(getCookieHeader, forKeyedSubscript: "getCookieHeader" as NSString)
        java?.setObject(getCookieValue, forKeyedSubscript: "__getCookieValue" as NSString)
        java?.setObject(setCookie, forKeyedSubscript: "setCookie" as NSString)
        java?.setObject(ajax, forKeyedSubscript: "ajax" as NSString)
        java?.setObject(ajaxAll, forKeyedSubscript: "ajaxAll" as NSString)
        java?.setObject(connect, forKeyedSubscript: "connect" as NSString)
        java?.setObject(directRequest, forKeyedSubscript: "__directRequest" as NSString)
        context.setObject(java, forKeyedSubscript: "java" as NSString)
        context.evaluateScript("""
            (function () {
              var getVariable = java.get;
              function responseOf(raw) {
                if (raw.error) throw new Error(raw.error);
                return {
                  statusCode: function () { return raw.code; },
                  body: function () { return raw.bodyText; },
                  header: function (name) {
                    var wanted = String(name).toLowerCase();
                    for (var key in raw.headers) if (key.toLowerCase() === wanted) return raw.headers[key];
                    return null;
                  },
                  headers: function () { return raw.headers; },
                  url: function () { return { toString: function () { return raw.urlText; } }; }
                };
              }
              java.get = function (url, headers, timeout) {
                var target = String(url);
                var networkURL = /^(https?:|data:)/i.test(target) || target[0] === '/' ||
                  target.indexOf('./') === 0 || target.indexOf('../') === 0;
                if (arguments.length === 1 && !networkURL) {
                  return getVariable(target);
                }
                return responseOf(java.__directRequest('GET', target, null, headers || {}, timeout));
              };
              java.getString = function (rule, content, isUrl) {
                return java.__getString(
                  String(rule == null ? '' : rule),
                  arguments.length < 2 || content == null ? src : content,
                  Boolean(isUrl)
                );
              };
              java.head = function (url, headers, timeout) {
                return responseOf(java.__directRequest('HEAD', String(url), null, headers || {}, timeout));
              };
              java.post = function (url, body, headers, timeout) {
                return responseOf(java.__directRequest('POST', String(url), body, headers || {}, timeout));
              };
              java.getCookie = function (tag, key) {
                return arguments.length < 2 || key == null
                  ? java.getCookieHeader(String(tag))
                  : java.__getCookieValue(String(tag), String(key));
              };
              java.getSource = function () { return typeof source === 'undefined' ? null : source; };
              java.getWebViewUA = function () { return '\(LegadoURLBuilder.defaultUserAgent)'; };
              java.getHeaderMap = function () {
                var map = typeof source === 'undefined' ? {} : source.getHeaderMap(true);
                map.put = function (key, value) { map[String(key)] = String(value); return value; };
                map.putAll = function (other) { for (var key in other) if (typeof other[key] !== 'function') map[key] = other[key]; };
                return map;
              };
              java.ajaxTestAll = function (urls, timeout) {
                return java.ajaxAll(urls, timeout).map(function (raw) {
                  var bodyText = raw.body;
                  raw.callTime = function () { return raw.code >= 200 && raw.code < 300 ? 0 : -1; };
                  raw.body = function () { return bodyText; };
                  return raw;
                });
              };
              java.clearTtsCache = function () { return true; };
            })();
            """)
    }

    private func loadDirectJavaScriptRequest(
        method: String,
        rawURL: String,
        body: String?,
        headers: [String: String],
        timeoutValue: Any?,
        executionContext: RuleExecutionContext
    ) throws -> HTTPResponse {
        let baseText = executionContext.baseURL.isEmpty
            ? executionContext.source?.bookSourceUrl ?? ""
            : executionContext.baseURL
        let baseURL = URL(string: baseText)
        guard let url = URL(string: rawURL, relativeTo: baseURL)?.absoluteURL,
              let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme) else {
            throw RuleEngineError.invalidInput(rule: rawURL, expected: "java.get/head/post URL")
        }
        let milliseconds = Self.number(timeoutValue) ?? 30_000
        var request = URLRequest(url: url, timeoutInterval: min(max(milliseconds / 1_000, 1), 180))
        request.httpMethod = method.uppercased()
        request.httpShouldHandleCookies = executionContext.source?.enabledCookieJar == true
        var requestHeaders = try executionContext.source.map { try BookSourceHeaderResolver().resolve($0) } ?? [:]
        requestHeaders.merge(headers) { _, explicit in explicit }
        if !requestHeaders.keys.contains(where: { $0.caseInsensitiveCompare("User-Agent") == .orderedSame }) {
            requestHeaders["User-Agent"] = ApplicationSettingsStore.shared.settings.effectiveUserAgent
        }
        requestHeaders.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }
        if method.caseInsensitiveCompare("POST") == .orderedSame {
            request.httpBody = Data((body ?? "").utf8)
        }
        if executionContext.source?.enabledCookieJar == true {
            let stored = LegadoCookieStore.shared.cookieHeader(for: rawURL)
            let explicit = request.value(forHTTPHeaderField: "Cookie") ?? ""
            let merged = Self.mergeCookieHeaders(stored, explicit)
            if !merged.isEmpty { request.setValue(merged, forHTTPHeaderField: "Cookie") }
        }
        let response: HTTPResponse
        if let redirectLoader = networkLoader as? any JavaScriptRedirectNetworkLoading {
            response = try redirectLoader.load(request, followRedirects: false)
        } else {
            response = try networkLoader.load(request)
        }
        if let cookie = response.headers.first(where: { $0.key.caseInsensitiveCompare("Set-Cookie") == .orderedSame })?.value {
            LegadoCookieStore.shared.setCookie(cookie, for: response.finalURL.absoluteString)
        }
        return response
    }

    private func loadJavaScriptRequest(
        _ rawURL: String,
        extraHeaders: [String: String],
        timeoutValue: Any?,
        executionContext: RuleExecutionContext
    ) throws -> HTTPResponse {
        guard !rawURL.isEmpty else {
            throw RuleEngineError.invalidInput(rule: rawURL, expected: "java.ajax/connect URL")
        }
        let source = executionContext.source
        var headers = try source.map { try BookSourceHeaderResolver().resolve($0) } ?? [:]
        headers.merge(extraHeaders) { _, extra in extra }
        let base = URL(string: executionContext.baseURL.isEmpty ? source?.bookSourceUrl ?? "" : executionContext.baseURL)
        let prepared = try urlBuilder.prepare(rawURL, baseURL: base, defaultHeaders: headers)
        if prepared.useWebView || prepared.webJavaScript != nil {
            throw RuleEngineError.unsupportedRule(rule: rawURL, feature: "JS 内 WKWebView 请求")
        }
        let milliseconds = Self.number(timeoutValue)
        let timeout = milliseconds.map { min(max($0 / 1_000, 1), 180) }
            ?? min(max(Double(source?.respondTime ?? 30_000) / 1_000, 5), 180)
        var request = prepared.urlRequest(timeout: timeout, handleCookies: source?.enabledCookieJar == true)
        if source?.enabledCookieJar == true {
            let stored = LegadoCookieStore.shared.cookieHeader(for: prepared.url.absoluteString)
            let explicit = request.value(forHTTPHeaderField: "Cookie") ?? ""
            let merged = Self.mergeCookieHeaders(stored, explicit)
            if !merged.isEmpty { request.setValue(merged, forHTTPHeaderField: "Cookie") }
        }
        let retryCount = max(prepared.retry, 0)
        let attempts = retryCount == Int.max ? Int.max : retryCount + 1
        var lastError: Error = HTTPClientError.nonHTTPResponse
        for attempt in 0..<attempts {
            do {
                var response = try networkLoader.load(request)
                response.requestedCharset = prepared.charset
                if let cookie = response.headers.first(where: { $0.key.caseInsensitiveCompare("Set-Cookie") == .orderedSame })?.value {
                    LegadoCookieStore.shared.setCookie(cookie, for: response.finalURL.absoluteString)
                }
                guard (200 ... 299).contains(response.statusCode) else {
                    throw HTTPClientError.statusResponse(response)
                }
                if prepared.responseType != nil {
                    response.data = Data(response.data.map { String(format: "%02x", $0) }.joined().utf8)
                    response.requestedCharset = "utf-8"
                } else if let bodyScript = prepared.bodyJavaScript {
                    let transformed = try JavaScriptRuleEvaluator(
                        maximumScriptLength: maximumScriptLength,
                        maximumResultLength: maximumResultLength,
                        networkLoader: networkLoader,
                        urlBuilder: urlBuilder
                    ).evaluate(
                        script: bodyScript,
                        result: .string(response.decodedText),
                        executionContext: executionContext
                    )
                    response.data = Data(transformed.value.stringValue.utf8)
                    response.requestedCharset = "utf-8"
                    response.requestVariables = transformed.variables
                }
                return response
            } catch {
                lastError = error
                guard case HTTPClientError.statusResponse = error, attempt + 1 < attempts else {
                    throw error
                }
            }
        }
        throw lastError
    }

    private func installSource(in context: JSContext, source: BookSource?, variables: AnyObject) {
        guard variables is VariableBoxProxy else { return }
        let sourceID = source?.bookSourceUrl ?? ""
        let object = JSValue(newObjectIn: context)
        let get: @convention(block) (String) -> String = { key in
            BookSourceRuntimeStore.shared.get(sourceID: sourceID, key: key)
        }
        let put: @convention(block) (String, Any?) -> String = { key, value in
            let text = Self.stringify(value)
            BookSourceRuntimeStore.shared.put(sourceID: sourceID, key: key, value: text)
            return text
        }
        let getLoginHeader: @convention(block) () -> Any? = {
            let value = BookSourceRuntimeStore.shared.get(sourceID: sourceID, key: "loginHeader")
            return value.isEmpty ? nil : value
        }
        let putLoginHeader: @convention(block) (Any?) -> String = {
            let value = Self.stringify($0)
            BookSourceRuntimeStore.shared.put(sourceID: sourceID, key: "loginHeader", value: value)
            return value
        }
        let getLoginInfo: @convention(block) () -> [String: Any] = {
            let value = BookSourceRuntimeStore.shared.get(sourceID: sourceID, key: "loginInfo")
            guard let data = value.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
            return object
        }
        let putLoginInfo: @convention(block) (Any?) -> String = {
            let value = Self.stringify($0)
            BookSourceRuntimeStore.shared.put(sourceID: sourceID, key: "loginInfo", value: value)
            return value
        }
        let getHeaderMap: @convention(block) (Bool) -> [String: String] = { includeLogin in
            var headers: [String: String] = [:]
            if let raw = source?.header?.trimmingCharacters(in: .whitespacesAndNewlines),
               raw.hasPrefix("{"),
               let data = raw.data(using: .utf8),
               let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                headers = object.mapValues { Self.stringify($0) }
            }
            if includeLogin {
                headers.merge(BookSourceRuntimeStore.shared.loginHeaders(sourceID: sourceID)) { _, login in login }
            }
            return headers
        }
        object?.setObject(get, forKeyedSubscript: "get" as NSString)
        object?.setObject(put, forKeyedSubscript: "put" as NSString)
        object?.setObject(getLoginHeader, forKeyedSubscript: "getLoginHeader" as NSString)
        object?.setObject(putLoginHeader, forKeyedSubscript: "putLoginHeader" as NSString)
        object?.setObject(getLoginInfo, forKeyedSubscript: "__getLoginInfoMap" as NSString)
        object?.setObject(putLoginInfo, forKeyedSubscript: "putLoginInfo" as NSString)
        object?.setObject(getHeaderMap, forKeyedSubscript: "getHeaderMap" as NSString)
        object?.setObject(source?.bookSourceName ?? "", forKeyedSubscript: "bookSourceName" as NSString)
        object?.setObject(source?.bookSourceUrl ?? "", forKeyedSubscript: "bookSourceUrl" as NSString)
        object?.setObject(source?.bookSourceGroup ?? "", forKeyedSubscript: "bookSourceGroup" as NSString)
        object?.setObject(source?.bookSourceType ?? 0, forKeyedSubscript: "bookSourceType" as NSString)
        object?.setObject(source?.bookUrlPattern ?? "", forKeyedSubscript: "bookUrlPattern" as NSString)
        object?.setObject(source?.customOrder ?? 0, forKeyedSubscript: "customOrder" as NSString)
        object?.setObject(source?.enabled ?? false, forKeyedSubscript: "enabled" as NSString)
        object?.setObject(source?.enabledExplore ?? false, forKeyedSubscript: "enabledExplore" as NSString)
        object?.setObject(source?.header ?? "", forKeyedSubscript: "header" as NSString)
        object?.setObject(source?.loginUrl ?? "", forKeyedSubscript: "loginUrl" as NSString)
        object?.setObject(source?.searchUrl ?? "", forKeyedSubscript: "searchUrl" as NSString)
        object?.setObject(source?.exploreUrl ?? "", forKeyedSubscript: "exploreUrl" as NSString)
        object?.setObject(source?.respondTime ?? 0, forKeyedSubscript: "respondTime" as NSString)
        object?.setObject(source?.weight ?? 0, forKeyedSubscript: "weight" as NSString)
        context.setObject(object, forKeyedSubscript: "source" as NSString)
        context.evaluateScript("""
            (function () {
              source.getKey = function () { return source.bookSourceUrl; };
              source.getTag = function () { return source.bookSourceName; };
              source.getLoginInfoMap = function () {
                var map = source.__getLoginInfoMap() || {};
                map.get = function (key) { return map[String(key)]; };
                map.put = function (key, value) { map[String(key)] = value; return value; };
                map.putAll = function (other) { for (var key in other) if (typeof other[key] !== 'function') map[key] = other[key]; };
                return map;
              };
              source.login = function () {
                if (!source.loginUrl) return null;
                (0, eval)(String(source.loginUrl));
                return typeof login === 'function' ? login() : null;
              };
            })();
            """)
    }

    private func installBook(in context: JSContext, book: Book?) {
        let object = JSValue(newObjectIn: context)
        let getName: @convention(block) () -> String = { book?.name ?? "" }
        let getAuthor: @convention(block) () -> String = { book?.author ?? "" }
        let getBookURL: @convention(block) () -> String = { book?.bookUrl ?? "" }
        let getCoverURL: @convention(block) () -> String = { book?.coverUrl ?? "" }
        let getTotal: @convention(block) () -> Int = { book?.totalChapterNum ?? 0 }
        object?.setObject(getName, forKeyedSubscript: "getName" as NSString)
        object?.setObject(getAuthor, forKeyedSubscript: "getAuthor" as NSString)
        object?.setObject(getBookURL, forKeyedSubscript: "getBookUrl" as NSString)
        object?.setObject(getCoverURL, forKeyedSubscript: "getCoverUrl" as NSString)
        object?.setObject(getTotal, forKeyedSubscript: "getTotalChapterNum" as NSString)
        object?.setObject(book?.name ?? "", forKeyedSubscript: "name" as NSString)
        object?.setObject(book?.author ?? "", forKeyedSubscript: "author" as NSString)
        object?.setObject(book?.bookUrl ?? "", forKeyedSubscript: "bookUrl" as NSString)
        object?.setObject(book?.tocUrl ?? "", forKeyedSubscript: "tocUrl" as NSString)
        object?.setObject(book?.origin ?? "", forKeyedSubscript: "origin" as NSString)
        object?.setObject(book?.originName ?? "", forKeyedSubscript: "originName" as NSString)
        object?.setObject(book?.kind ?? "", forKeyedSubscript: "kind" as NSString)
        object?.setObject(book?.coverUrl ?? "", forKeyedSubscript: "coverUrl" as NSString)
        object?.setObject(book?.intro ?? "", forKeyedSubscript: "intro" as NSString)
        object?.setObject(book?.type ?? 0, forKeyedSubscript: "type" as NSString)
        object?.setObject(book?.group ?? 0, forKeyedSubscript: "group" as NSString)
        object?.setObject(book?.latestChapterTitle ?? "", forKeyedSubscript: "latestChapterTitle" as NSString)
        object?.setObject(book?.totalChapterNum ?? 0, forKeyedSubscript: "totalChapterNum" as NSString)
        object?.setObject(book?.durChapterIndex ?? 0, forKeyedSubscript: "durChapterIndex" as NSString)
        object?.setObject(book?.durChapterTitle ?? "", forKeyedSubscript: "durChapterTitle" as NSString)
        object?.setObject(book?.durChapterPos ?? 0, forKeyedSubscript: "durChapterPos" as NSString)
        object?.setObject(book?.wordCount ?? "", forKeyedSubscript: "wordCount" as NSString)
        object?.setObject(book?.variable ?? "", forKeyedSubscript: "variable" as NSString)
        context.setObject(object, forKeyedSubscript: "book" as NSString)
    }

    private func installChapter(in context: JSContext, chapter: BookChapter?) {
        let object = JSValue(newObjectIn: context)
        let getTitle: @convention(block) () -> String = { chapter?.title ?? "" }
        let getIndex: @convention(block) () -> Int = { chapter?.index ?? 0 }
        let getURL: @convention(block) () -> String = { chapter?.url ?? "" }
        object?.setObject(getTitle, forKeyedSubscript: "getTitle" as NSString)
        object?.setObject(getIndex, forKeyedSubscript: "getIndex" as NSString)
        object?.setObject(getURL, forKeyedSubscript: "getUrl" as NSString)
        object?.setObject(chapter?.title ?? "", forKeyedSubscript: "title" as NSString)
        object?.setObject(chapter?.index ?? 0, forKeyedSubscript: "index" as NSString)
        object?.setObject(chapter?.url ?? "", forKeyedSubscript: "url" as NSString)
        object?.setObject(chapter?.baseUrl ?? "", forKeyedSubscript: "baseUrl" as NSString)
        object?.setObject(chapter?.bookUrl ?? "", forKeyedSubscript: "bookUrl" as NSString)
        object?.setObject(chapter?.isVolume ?? false, forKeyedSubscript: "isVolume" as NSString)
        object?.setObject(chapter?.isVip ?? false, forKeyedSubscript: "isVip" as NSString)
        object?.setObject(chapter?.isPay ?? false, forKeyedSubscript: "isPay" as NSString)
        object?.setObject(chapter?.resourceUrl ?? "", forKeyedSubscript: "resourceUrl" as NSString)
        object?.setObject(chapter?.tag ?? "", forKeyedSubscript: "tag" as NSString)
        object?.setObject(chapter?.wordCount ?? "", forKeyedSubscript: "wordCount" as NSString)
        object?.setObject(chapter?.variable ?? "", forKeyedSubscript: "variable" as NSString)
        context.setObject(object, forKeyedSubscript: "chapter" as NSString)
        context.setObject(chapter?.title ?? "", forKeyedSubscript: "title" as NSString)
    }

    private func evaluateStringRule(
        _ rule: String,
        content: JSONValue,
        isURL: Bool,
        executionContext: RuleExecutionContext
    ) throws -> String {
        let trimmedRule = rule.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedRule.isEmpty else { return "" }

        if case .object(let object) = content,
           let direct = object[trimmedRule] {
            return resolveJavaScriptRuleURL(direct.stringValue, enabled: isURL, context: executionContext)
        }
        let (combined, plan) = try stringRuleValues(trimmedRule, content: content, executionContext: executionContext)
        var result = combined.joined(separator: "\n")
        if let branch = plan.branches.first, let pattern = branch.replacePattern, !pattern.isEmpty {
            result = try RegexEvaluator().replacing(pattern: pattern, in: result, with: branch.replacement, firstOnly: branch.replaceFirst)
        }
        return resolveJavaScriptRuleURL(result, enabled: isURL, context: executionContext)
    }

    /// `java.getStringList`: each value a rule finds, replaced and resolved one by one.
    func evaluateStringRuleValues(
        _ rule: String,
        content: JSONValue,
        isURL: Bool,
        executionContext: RuleExecutionContext
    ) throws -> [String] {
        let trimmedRule = rule.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedRule.isEmpty else { return [] }
        if case .object(let object) = content, let direct = object[trimmedRule] {
            if case .array(let items) = direct {
                return items.map { resolveJavaScriptRuleURL($0.stringValue, enabled: isURL, context: executionContext) }
            }
            return [resolveJavaScriptRuleURL(direct.stringValue, enabled: isURL, context: executionContext)]
        }
        let (combined, plan) = try stringRuleValues(trimmedRule, content: content, executionContext: executionContext)
        return try combined.map { value in
            var value = value
            if let branch = plan.branches.first, let pattern = branch.replacePattern, !pattern.isEmpty {
                value = try RegexEvaluator().replacing(pattern: pattern, in: value, with: branch.replacement, firstOnly: branch.replaceFirst)
            }
            return resolveJavaScriptRuleURL(value, enabled: isURL, context: executionContext)
        }
    }

    private func stringRuleValues(
        _ trimmedRule: String,
        content: JSONValue,
        executionContext: RuleExecutionContext
    ) throws -> ([String], RulePlan) {

        let jsonContent: JSONValue?
        if case .string(let text) = content { jsonContent = try? JSONValue.decode(data: Data(text.utf8)) }
        else { jsonContent = content }
        let plan = try RuleExpressionParser().parse(trimmedRule, inputLooksLikeJSON: jsonContent != nil)
        var branchResults: [[String]] = []
        for branch in plan.branches {
            var values: [String]
            if branch.expression.isEmpty {
                values = [content.stringValue]
            } else {
                switch branch.mode {
                case .css:
                    values = try HTMLRuleEvaluator().extractCSS(
                        branch.expression,
                        html: content.stringValue,
                        baseURL: executionContext.baseURL,
                        isFragment: executionContext.isHTMLFragment
                    )
                case .xpath:
                    values = try HTMLRuleEvaluator().extractXPath(branch.expression, html: content.stringValue, isFragment: executionContext.isHTMLFragment)
                case .jsonPath:
                    let json: JSONValue
                    if case .string(let text) = content {
                        json = try JSONValue.decode(data: Data(text.utf8))
                    } else {
                        json = content
                    }
                    values = RuleEvaluation(values: try JSONPathEvaluator().evaluateRule(branch.expression, in: json)).strings
                case .regex:
                    values = try RegexEvaluator().captureGroups(pattern: branch.expression, input: content.stringValue)
                        .map { $0.count > 1 ? $0.dropFirst().joined() : $0.first ?? "" }
                case .javaScript:
                    values = [try evaluate(
                        script: branch.expression,
                        result: content,
                        executionContext: executionContext
                    ).value.stringValue]
                case .webJavaScript:
                    throw RuleEngineError.unsupportedRule(rule: branch.expression, feature: "java.getString WebView JavaScript")
                }
            }
            if plan.combination == .fallback, values.joined(separator: "\n").isEmpty { values = [] }
            branchResults.append(values)
            if plan.combination == .fallback, !values.isEmpty { break }
        }

        let combined: [String]
        switch plan.combination {
        case .single, .concatenate:
            combined = branchResults.flatMap { $0 }
        case .fallback:
            combined = branchResults.first(where: { !$0.isEmpty }) ?? []
        case .interleave:
            guard let firstCount = branchResults.first?.count else { return ([], plan) }
            combined = (0..<firstCount).flatMap { index in
                branchResults.compactMap { $0.indices.contains(index) ? $0[index] : nil }
            }
        }
        return (combined, plan)
    }

    private func resolveJavaScriptRuleURL(
        _ value: String,
        enabled: Bool,
        context: RuleExecutionContext
    ) -> String {
        guard enabled else { return value }
        let baseText = context.baseURL.isEmpty ? context.source?.bookSourceUrl ?? "" : context.baseURL
        guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return baseText }
        guard let baseURL = URL(string: baseText),
              let absolute = URL(string: value, relativeTo: baseURL)?.absoluteURL else { return value }
        return absolute.absoluteString
    }

    private func rejectUnboundedExecution(_ script: String) throws {
        let compact = script.replacingOccurrences(of: #"\s+"#, with: "", options: .regularExpression).lowercased()
        // eval runs code no less bounded than the script itself; sources use it to unpack
        // scripts the site serves
        let rejected = ["while(true)", "while(1)", "for(;;)", "functionconstructor("]
        if let token = rejected.first(where: compact.contains) {
            throw RuleEngineError.resourceLimit(rule: script, detail: "JavaScript 包含未受控执行结构：\(token)")
        }
    }

    static func stringify(_ value: Any?) -> String {
        guard let value else { return "" }
        if let value = value as? String { return value }
        if JSONSerialization.isValidJSONObject(value),
           let data = try? JSONSerialization.data(withJSONObject: value),
           let string = String(data: data, encoding: .utf8) { return string }
        return String(describing: value)
    }

    private static func firstURL(_ value: Any?) -> String {
        if let values = value as? [Any], let first = values.first { return stringify(first) }
        return stringify(value)
    }

    private static func number(_ value: Any?) -> Double? {
        if let value = value as? NSNumber { return value.doubleValue }
        return Double(stringify(value))
    }

    private static func hexBytes(_ value: String) -> [UInt8] {
        let characters = Array(value.trimmingCharacters(in: .whitespacesAndNewlines))
        guard characters.count.isMultiple(of: 2) else { return [] }
        return stride(from: 0, to: characters.count, by: 2).compactMap { index in
            UInt8(String(characters[index ... index + 1]), radix: 16)
        }
    }

    static func byteData(from value: Any?) -> Data {
        let values: [Any]
        if let value = value as? [Any] {
            values = value
        } else if let value = value as? NSArray {
            values = value.map { $0 }
        } else {
            return Data()
        }
        return Data(values.compactMap { item in
            if let number = item as? NSNumber { return UInt8(truncatingIfNeeded: number.intValue) }
            if let number = Int(stringify(item)) { return UInt8(truncatingIfNeeded: number) }
            return nil
        })
    }

    private static let javaImporterBootstrap = #"""
        (function (global) {
          'use strict';
          var NativeString = global.String;
          global.__legadoUnboxString = function (value) {
            return Object.prototype.toString.call(value) === '[object String]' ? NativeString(value) : value;
          };
          function javaClass(name, value) {
            Object.defineProperty(value, '__javaSimpleName', { value: name });
            return Object.freeze(value);
          }
          function checkedBytes(value) {
            if (!Array.isArray(value)) throw new TypeError('Java byte[] required');
            return value;
          }
          function JavaString(value) {
            var text = new NativeString(Array.isArray(value) ? __legadoUTF8String(value) : (value == null ? '' : value));
            Object.defineProperty(text, 'getBytes', {
              value: function (charset) {
                if (charset && !/^utf-?8$/i.test(NativeString(charset))) {
                  throw new Error('Unsupported charset: ' + charset);
                }
                return __legadoUTF8Bytes(NativeString(this));
              }
            });
            return text;
          }
          function SecretKeySpec(bytes, algorithm) {
            if (!(this instanceof SecretKeySpec)) return new SecretKeySpec(bytes, algorithm);
            this.key = checkedBytes(bytes).slice();
            this.algorithm = NativeString(algorithm || '');
            Object.freeze(this.key);
            Object.freeze(this);
          }
          function IvParameterSpec(bytes) {
            if (!(this instanceof IvParameterSpec)) return new IvParameterSpec(bytes);
            this.bytes = checkedBytes(bytes).slice();
            if (this.bytes.length !== 16) throw new Error('AES IV must contain 16 bytes');
            Object.freeze(this.bytes);
            Object.freeze(this);
          }
          var Cipher = javaClass('Cipher', {
            ENCRYPT_MODE: 1,
            DECRYPT_MODE: 2,
            getInstance: function (algorithm) {
              if (NativeString(algorithm).toUpperCase() !== 'AES/CBC/PKCS5PADDING') {
                throw new Error('Unsupported Cipher algorithm: ' + algorithm);
              }
              var key = null, iv = null, operation = null;
              return {
                init: function (mode, spec, parameters) {
                  if ((mode !== 1 && mode !== 2) || !(spec instanceof SecretKeySpec) ||
                      spec.algorithm.toUpperCase() !== 'AES' || !(parameters instanceof IvParameterSpec)) {
                    throw new TypeError('AES key, IV and cipher mode required');
                  }
                  operation = mode; key = spec.key; iv = parameters.bytes;
                },
                doFinal: function (bytes) {
                  if (key === null) throw new Error('Cipher not initialized');
                  var result = __legadoAESCBC(operation, key, iv, checkedBytes(bytes));
                  if (!Array.isArray(result)) throw new Error('AES/CBC operation failed');
                  return result;
                }
              };
            }
          });
          var Mac = javaClass('Mac', {
            getInstance: function (algorithm) {
              if (NativeString(algorithm).toUpperCase() !== 'HMACSHA1') {
                throw new Error('Unsupported Mac algorithm: ' + algorithm);
              }
              var key = null;
              return {
                init: function (spec) {
                  if (!(spec instanceof SecretKeySpec) || spec.algorithm.toUpperCase() !== 'HMACSHA1') {
                    throw new TypeError('HmacSHA1 SecretKeySpec required');
                  }
                  key = spec.key;
                },
                doFinal: function (bytes) {
                  if (key === null) throw new Error('Mac not initialized');
                  return __legadoHmacSHA1(key, checkedBytes(bytes));
                }
              };
            }
          });
          javaClass('SecretKeySpec', SecretKeySpec);
          javaClass('IvParameterSpec', IvParameterSpec);
          javaClass('String', JavaString);
          var Base64 = javaClass('Base64', {
            DEFAULT: 0,
            NO_WRAP: 2,
            encodeToString: function (bytes) { return __legadoBase64EncodeBytes(checkedBytes(bytes)); },
            decode: function (value) { return __legadoBase64DecodeBytes(NativeString(value)); },
            getDecoder: function () { return Object.freeze({ decode: this.decode }); },
            getEncoder: function () { return Object.freeze({ encodeToString: this.encodeToString }); }
          });
          var Arrays = javaClass('Arrays', {
            copyOfRange: function (bytes, from, to) {
              checkedBytes(bytes);
              if (!Number.isInteger(from) || !Number.isInteger(to) || from < 0 || from > bytes.length || to < from || to - from > 2097152) {
                throw new RangeError('Invalid byte array range');
              }
              var copied = bytes.slice(from, to);
              while (copied.length < to - from) copied.push(0);
              return copied;
            }
          });
          var URLEncoder = javaClass('URLEncoder', {
            encode: function (value, charset) {
              if (charset && !/^utf-?8$/i.test(NativeString(charset))) {
                throw new Error('Unsupported charset: ' + charset);
              }
              return __legadoFormURLEncode(NativeString(value));
            }
          });
          var DatatypeConverter = javaClass('DatatypeConverter', {
            printBase64Binary: function (bytes) { return __legadoBase64EncodeBytes(checkedBytes(bytes)); },
            parseBase64Binary: function (value) { return __legadoBase64DecodeBytes(NativeString(value)); },
            printHexBinary: function (bytes) { return __legadoHexEncodeBytes(checkedBytes(bytes)); }
          });
          var packages = {
            org: { jsoup: { Jsoup: global.__legadoJsoup } },
            javax: {
              crypto: { Mac: Mac, Cipher: Cipher, spec: { SecretKeySpec: SecretKeySpec, IvParameterSpec: IvParameterSpec } },
              xml: { bind: { DatatypeConverter: DatatypeConverter } }
            },
            java: {
              net: { URLEncoder: URLEncoder },
              lang: { String: JavaString, Thread: global.__legadoThread },
              util: { Base64: Base64, Arrays: Arrays, HashMap: global.__legadoHashMap, ArrayList: global.__legadoArrayList }
            },
            android: { util: { Base64: Base64 } }
          };
          Object.freeze(packages.javax.crypto.spec);
          Object.freeze(packages.javax.crypto);
          Object.freeze(packages.javax.xml.bind);
          Object.freeze(packages.javax.xml);
          Object.freeze(packages.javax);
          Object.freeze(packages.java.net);
          Object.freeze(packages.java.lang);
          Object.freeze(packages.java.util);
          Object.freeze(packages.java);
          Object.freeze(packages.android.util);
          Object.freeze(packages.org.jsoup);
          Object.freeze(packages.org);
          Object.freeze(packages.android);
          global.Packages = Object.freeze(packages);
          global.JavaImporter = Object.freeze(function () {
            var imported = Object.create(null);
            var allowedPackages = [packages.java.lang, packages.java.net, packages.java.util,
              packages.javax.crypto, packages.javax.crypto.spec, packages.javax.xml.bind, packages.android.util,
              packages.org.jsoup];
            function addClass(value) {
              if (!value || typeof value.__javaSimpleName !== 'string') throw new TypeError('Unsupported Java class import');
              if (!Object.prototype.hasOwnProperty.call(imported, value.__javaSimpleName)) {
                Object.defineProperty(imported, value.__javaSimpleName, { value: value, enumerable: true });
              }
            }
            function addPackage(value) {
              if (allowedPackages.indexOf(value) < 0) throw new TypeError('Unsupported Java package import');
              Object.keys(value).forEach(function (name) {
                if (value[name] && typeof value[name].__javaSimpleName === 'string') addClass(value[name]);
              });
            }
            Object.defineProperty(imported, 'importPackage', { value: function () {
              for (var i = 0; i < arguments.length; i++) addPackage(arguments[i]);
            }});
            Object.defineProperty(imported, 'importClass', { value: function () {
              for (var i = 0; i < arguments.length; i++) addClass(arguments[i]);
            }});
            for (var index = 0; index < arguments.length; index++) {
              var value = arguments[index];
              if (allowedPackages.indexOf(value) >= 0) addPackage(value); else addClass(value);
            }
            return imported;
          });
        })(this);
        """#

    private static func formURLEncode(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._*"))
        return value.unicodeScalars.map { scalar in
            if scalar == " " { return "+" }
            if scalar.isASCII, allowed.contains(scalar) { return String(scalar) }
            return String(scalar).utf8.map { String(format: "%%%02X", $0) }.joined()
        }.joined()
    }

    private static func headerMap(_ value: Any?) -> [String: String] {
        if let values = value as? [String: String] { return values }
        if let values = value as? [String: Any] { return values.mapValues(stringify) }
        let text = stringify(value)
        guard let data = text.data(using: .utf8),
              let values = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return values.mapValues(stringify)
    }

    private static func mergeCookieHeaders(_ stored: String, _ explicit: String) -> String {
        var order: [String] = []
        var values: [String: String] = [:]
        for header in [stored, explicit] {
            for part in header.split(separator: ";") {
                let pair = part.split(separator: "=", maxSplits: 1).map(String.init)
                guard pair.count == 2 else { continue }
                let name = pair[0].trimmingCharacters(in: .whitespaces)
                if values[name] == nil { order.append(name) }
                values[name] = pair[1].trimmingCharacters(in: .whitespaces)
            }
        }
        return order.compactMap { name in values[name].map { "\(name)=\($0)" } }.joined(separator: "; ")
    }
}

private protocol VariableBoxProxy: AnyObject {
    func get(_ key: String) -> String
    @discardableResult func put(_ key: String, _ value: String) -> String
}

private final class JSVariableBox: VariableBoxProxy {
    var values: [String: String]

    init(_ values: [String: String]) {
        self.values = values
    }

    func get(_ key: String) -> String { values[key] ?? "" }

    @discardableResult
    func put(_ key: String, _ value: String) -> String {
        values[key] = value
        return value
    }
}

public final class BookSourceRuntimeStore: @unchecked Sendable {
    public static let shared = BookSourceRuntimeStore()

    private let lock = NSLock()
    private var values: [String: [String: String]] = [:]
    private let persistent = PersistentRuntimeCache.shared

    public func get(sourceID: String, key: String) -> String {
        lock.lock()
        defer { lock.unlock() }
        if let value = values[sourceID]?[key] { return value }
        let cacheKey = persistentKey(sourceID: sourceID, key: key)
        let value = persistent.get(cacheKey) ?? ""
        if !value.isEmpty { values[sourceID, default: [:]][key] = value }
        return value
    }

    public func put(sourceID: String, key: String, value: String) {
        lock.lock()
        values[sourceID, default: [:]][key] = value
        lock.unlock()
        persistent.put(persistentKey(sourceID: sourceID, key: key), value: value)
    }

    public func loginHeaders(sourceID: String) -> [String: String] {
        let value = get(sourceID: sourceID, key: "loginHeader")
        guard let data = value.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return object.mapValues { String(describing: $0) }
    }

    private func persistentKey(sourceID: String, key: String) -> String {
        key == "loginHeader" ? "loginHeader_\(sourceID)" : "v_\(sourceID)_\(key)"
    }
}
