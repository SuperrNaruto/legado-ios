#if canImport(WebKit)
@preconcurrency import WebKit
import Foundation

/// Runs a source's `webView` requests in a hidden web view: the page's HTML once it has
/// loaded and its scripts have run, with the cookies it set.
public final class WKSourceWebViewExecutor: NSObject, SourceWebViewRequestExecuting, @unchecked Sendable {
    override public init() {}

    @MainActor
    public func execute(_ prepared: PreparedRequest, source: BookSource, timeout: TimeInterval) async throws -> HTTPResponse {
        let override = ApplicationSettingsStore.shared.settings.timeoutSeconds
        return try await BackgroundWebViewRequest(prepared: prepared, source: source, timeout: override > 0 ? Double(override) : timeout).run()
    }
}

@MainActor
private final class BackgroundWebViewRequest: NSObject, WKNavigationDelegate {
    private let prepared: PreparedRequest
    private let source: BookSource
    private let timeout: TimeInterval
    private let webView: WKWebView
    private var continuation: CheckedContinuation<HTTPResponse, Error>?
    private var responseStatus = 200
    private var responseHeaders: [String: String] = [:]
    private var completed = false
    private var timeoutTask: Task<Void, Never>?
    private var settleTask: Task<Void, Never>?
    private var capturing = false
    /// How long a parsed page may load what it embeds (captchas, trackers) before its
    /// document is taken as it is.
    private static let subresourceGrace: TimeInterval = 10

    init(prepared: PreparedRequest, source: BookSource, timeout: TimeInterval) {
        self.prepared = prepared
        self.source = source
        self.timeout = timeout
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        webView = WKWebView(frame: .zero, configuration: configuration)
        // as Legado's web view does: the source's User-Agent, or the desktop one requests
        // use; the web view's own would get sites' mobile pages, which rules do not read
        webView.customUserAgent = prepared.headers.first { $0.key.caseInsensitiveCompare("User-Agent") == .orderedSame }?.value
            ?? LegadoURLBuilder.defaultUserAgent
        super.init()
        webView.navigationDelegate = self
    }

    func run() async throws -> HTTPResponse {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                self.continuation = continuation
                installRequestCookies { [weak self] in self?.startLoading() }
            }
        } onCancel: {
            Task { @MainActor [weak self] in self?.finish(.failure(CancellationError())) }
        }
    }

    private func startLoading() {
        timeoutTask = Task { [weak self] in
            let seconds = min(max(self?.timeout ?? 30, 1), 300)
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await MainActor.run { self?.finish(.failure(URLError(.timedOut))) }
        }
        webView.load(prepared.urlRequest(timeout: timeout, handleCookies: true))
    }

    private func installRequestCookies(completion: @escaping () -> Void) {
        guard let header = prepared.headers.first(where: { $0.key.caseInsensitiveCompare("Cookie") == .orderedSame })?.value,
              let host = prepared.url.host, !header.isEmpty else {
            completion()
            return
        }
        let cookies = header.split(separator: ";").compactMap { part -> HTTPCookie? in
            let pair = part.split(separator: "=", maxSplits: 1).map(String.init)
            guard pair.count == 2 else { return nil }
            return HTTPCookie(properties: [
                .name: pair[0].trimmingCharacters(in: .whitespaces),
                .value: pair[1],
                .domain: host,
                .path: "/",
                .secure: prepared.url.scheme == "https" ? "TRUE" : "FALSE"
            ])
        }
        guard !cookies.isEmpty else { completion(); return }
        let group = DispatchGroup()
        for cookie in cookies {
            group.enter()
            webView.configuration.websiteDataStore.httpCookieStore.setCookie(cookie) { group.leave() }
        }
        group.notify(queue: .main, execute: completion)
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationResponse: WKNavigationResponse,
        decisionHandler: @escaping @MainActor (WKNavigationResponsePolicy) -> Void
    ) {
        // a frame's response is not the page's
        if navigationResponse.isForMainFrame, let response = navigationResponse.response as? HTTPURLResponse {
            responseStatus = response.statusCode
            responseHeaders = response.allHeaderFields.reduce(into: [:]) { result, entry in
                result[String(describing: entry.key)] = String(describing: entry.value)
            }
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation?) {
        settleTask?.cancel()
    }

    /// A page's own document, once parsed, is what the source reads; what it embeds may
    /// keep it loading well past that, so it is taken after a grace if it has not finished.
    func webView(_ webView: WKWebView, didCommit navigation: WKNavigation?) {
        settleTask?.cancel()
        guard !Self.isChallenge(responseStatus) else { return }
        settleTask = Task { [weak self] in
            while let self, !Task.isCancelled,
                  (try? await webView.evaluateJavaScript("document.readyState") as? String) == "loading" {
                try? await Task.sleep(nanoseconds: 250_000_000)
            }
            let delay = max(Self.subresourceGrace, Double(self?.prepared.webViewDelayMilliseconds ?? 0) / 1_000)
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard let self, !Task.isCancelled, !completed else { return }
            await capture()
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation?) {
        Task { [weak self] in
            guard let self else { return }
            if prepared.webViewDelayMilliseconds > 0 {
                try? await Task.sleep(nanoseconds: UInt64(max(0, prepared.webViewDelayMilliseconds)) * 1_000_000)
            }
            guard !Task.isCancelled, !completed else { return }
            // A challenge page (Cloudflare's, Qidian's probe) loads the real page once its
            // script has run; that navigation finishes in its turn.
            if await navigationFollows() { return }
            await capture()
        }
    }

    /// The page as it is now, with the cookies it set.
    private func capture() async {
        // the page may finish loading while its grace is being taken
        guard !completed, !capturing else { return }
        capturing = true
        if let script = prepared.webJavaScript, !script.isEmpty {
            do { _ = try await webView.evaluateJavaScript(script) }
            catch { finish(.failure(error)); return }
        }
        guard !completed else { return }
        do {
            let html = try await webView.evaluateJavaScript("document.documentElement.outerHTML") as? String ?? ""
            let cookies = await webView.configuration.websiteDataStore.httpCookieStore.allCookies()
            cookies.forEach(HTTPCookieStorage.shared.setCookie)
            let cookieHeader = HTTPCookie.requestHeaderFields(with: cookies)["Cookie"] ?? ""
            if !cookieHeader.isEmpty {
                await SourceNetworkPolicy.shared.setCookieHeader(cookieHeader, sourceID: source.id, url: prepared.url)
            }
            var headers = responseHeaders
            if !cookieHeader.isEmpty { headers["Set-Cookie"] = cookieHeader }
            finish(.success(.init(
                data: Data(html.utf8),
                statusCode: responseStatus,
                headers: headers,
                finalURL: webView.url ?? prepared.url,
                requestedCharset: "utf-8"
            )))
        } catch {
            finish(.failure(error))
        }
    }

    private static func isChallenge(_ status: Int) -> Bool {
        [202, 403, 429, 503].contains(status)
    }

    private func navigationFollows() async -> Bool {
        let challenged = Self.isChallenge(responseStatus)
        let deadline = Date().addingTimeInterval(challenged ? 8 : 0)
        repeat {
            if webView.isLoading || completed { return true }
            try? await Task.sleep(nanoseconds: 100_000_000)
        } while Date() < deadline
        return webView.isLoading
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation?, withError error: Error) {
        finish(.failure(error))
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation?, withError error: Error) {
        finish(.failure(error))
    }

    private func finish(_ result: Result<HTTPResponse, Error>) {
        guard !completed else { return }
        completed = true
        timeoutTask?.cancel()
        settleTask?.cancel()
        webView.stopLoading()
        continuation?.resume(with: result)
        continuation = nil
    }
}

private extension WKHTTPCookieStore {
    func allCookies() async -> [HTTPCookie] {
        await withCheckedContinuation { continuation in
            getAllCookies { continuation.resume(returning: $0) }
        }
    }
}
#endif
