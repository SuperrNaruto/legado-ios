import CommonCrypto
import Foundation
import JavaScriptCore
import SwiftSoup

/// What Legado's scripts reach on Android that the other parts of the bridge do not provide:
/// Jsoup elements, a few Java classes, `java.*` and `source.*` helpers, and `cache`.
extension JavaScriptRuleEvaluator {
    /// Classes, installed before the Java importer, which offers them as packages.
    func installAndroidClasses(in context: JSContext) {
        let select: @convention(block) (String, String) -> [String] = { html, css in
            guard let root = try? Self.htmlRoot(html) else { return [] }
            return (try? root.select(css).array().map { try $0.outerHtml() }) ?? []
        }
        let text: @convention(block) (String) -> String = { html in
            (try? Self.htmlRoot(html).text()) ?? ""
        }
        let ownText: @convention(block) (String) -> String = { html in
            (try? Self.htmlElement(html)?.ownText()) ?? ""
        }
        let inner: @convention(block) (String) -> String = { html in
            guard let element = try? Self.htmlElement(html) else { return (try? Self.htmlRoot(html).html()) ?? "" }
            return (try? element.html()) ?? ""
        }
        let attribute: @convention(block) (String, String) -> String = { html, name in
            (try? Self.htmlElement(html)?.attr(name)) ?? ""
        }
        let children: @convention(block) (String) -> [String] = { html in
            guard let element = try? Self.htmlElement(html) else { return [] }
            return (try? element.children().array().map { try $0.outerHtml() }) ?? []
        }
        let tagName: @convention(block) (String) -> String = { html in
            (try? Self.htmlElement(html)?.tagName()) ?? ""
        }
        let sleep: @convention(block) (Double) -> Void = { milliseconds in
            // a script waits between requests; a long wait is a stuck script
            Thread.sleep(forTimeInterval: min(max(milliseconds, 0), 5_000) / 1_000)
        }
        context.setObject(select, forKeyedSubscript: "__legadoHTMLSelect" as NSString)
        context.setObject(text, forKeyedSubscript: "__legadoHTMLText" as NSString)
        context.setObject(ownText, forKeyedSubscript: "__legadoHTMLOwnText" as NSString)
        context.setObject(inner, forKeyedSubscript: "__legadoHTMLInner" as NSString)
        context.setObject(attribute, forKeyedSubscript: "__legadoHTMLAttr" as NSString)
        context.setObject(children, forKeyedSubscript: "__legadoHTMLChildren" as NSString)
        context.setObject(tagName, forKeyedSubscript: "__legadoHTMLTagName" as NSString)
        context.setObject(sleep, forKeyedSubscript: "__legadoSleep" as NSString)
        context.evaluateScript(Self.androidClassesBootstrap)
    }

    /// Helpers on `java`, `source` and `cache`, installed once those objects are.
    func installAndroidAPIs(in context: JSContext, result: JSONValue, executionContext: RuleExecutionContext) {
        let sourceID = executionContext.source?.bookSourceUrl ?? ""
        let elements: @convention(block) (String, Any?) -> [String] = { rule, content in
            let input = content.map(JSONValue.bridge) ?? executionContext.content ?? result
            return (try? self.elementFragments(rule, html: input.stringValue, executionContext: executionContext)) ?? []
        }
        let stringList: @convention(block) (String, Any?, Bool) -> [String] = { rule, content, isURL in
            let input = content.map(JSONValue.bridge) ?? executionContext.content ?? result
            return (try? self.evaluateStringRuleValues(rule, content: input, isURL: isURL, executionContext: executionContext)) ?? []
        }
        let chinese: @convention(block) (String, Bool) -> String = { text, toSimplified in
            text.applyingTransform(StringTransform("Hant-Hans"), reverse: !toSimplified) ?? text
        }
        let aes: @convention(block) (Any?, String, String, String, Bool, Bool) -> [Int]? = { data, key, transformation, iv, decrypt, base64Key in
            let keyData = base64Key ? (Data(base64Encoded: key) ?? Data()) : Data(key.utf8)
            return Self.aes(Self.byteData(from: data), key: keyData, iv: Data(iv.utf8), transformation: transformation, decrypt: decrypt)?
                .map { Int(Int8(bitPattern: $0)) }
        }
        let sourceVariable: @convention(block) () -> String = {
            BookSourceRuntimeStore.shared.get(sourceID: sourceID, key: "sourceVariable")
        }
        let setSourceVariable: @convention(block) (Any?) -> Void = {
            BookSourceRuntimeStore.shared.put(sourceID: sourceID, key: "sourceVariable", value: Self.stringify($0))
        }
        let loginHeaders: @convention(block) () -> [String: String] = {
            BookSourceRuntimeStore.shared.loginHeaders(sourceID: sourceID)
        }
        let cacheGet: @convention(block) (String) -> String? = { key in
            let stored = BookSourceRuntimeStore.shared.get(sourceID: "__cache__", key: key)
            guard let data = stored.data(using: .utf8),
                  let entry = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let value = entry["v"] as? String else { return nil }
            if let expiry = entry["e"] as? Double, expiry > 0, Date().timeIntervalSince1970 > expiry { return nil }
            return value
        }
        let cachePut: @convention(block) (String, Any?, Double) -> Void = { key, value, seconds in
            let entry: [String: Any] = [
                "v": Self.stringify(value),
                // a negative time is a value already gone
                "e": seconds > 0 ? Date().timeIntervalSince1970 + seconds : (seconds < 0 ? 1 : 0)
            ]
            let data = (try? JSONSerialization.data(withJSONObject: entry)) ?? Data()
            BookSourceRuntimeStore.shared.put(sourceID: "__cache__", key: key, value: String(decoding: data, as: UTF8.self))
        }
        context.setObject(elements, forKeyedSubscript: "__legadoElements" as NSString)
        context.setObject(stringList, forKeyedSubscript: "__legadoStringList" as NSString)
        context.setObject(chinese, forKeyedSubscript: "__legadoChinese" as NSString)
        context.setObject(aes, forKeyedSubscript: "__legadoAES" as NSString)
        context.setObject(sourceVariable, forKeyedSubscript: "__legadoSourceVariable" as NSString)
        context.setObject(setSourceVariable, forKeyedSubscript: "__legadoSetSourceVariable" as NSString)
        context.setObject(loginHeaders, forKeyedSubscript: "__legadoLoginHeaders" as NSString)
        context.setObject(cacheGet, forKeyedSubscript: "__legadoCacheGet" as NSString)
        context.setObject(cachePut, forKeyedSubscript: "__legadoCachePut" as NSString)
        context.evaluateScript(Self.androidAPIsBootstrap)
    }

    /// The elements a rule selects, as HTML.
    private func elementFragments(_ rule: String, html: String, executionContext: RuleExecutionContext) throws -> [String] {
        let trimmed = rule.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [html] }
        let plan = try RuleExpressionParser().parse(trimmed, inputLooksLikeJSON: false)
        var fragments: [String] = []
        for branch in plan.branches {
            switch branch.mode {
                case .xpath:
                    fragments += try HTMLRuleEvaluator().selectXPathFragments(branch.expression, html: html)
                default:
                    fragments += try HTMLRuleEvaluator().selectCSSFragments(
                        branch.expression, html: html, baseURL: executionContext.baseURL, isFragment: executionContext.isHTMLFragment
                    )
            }
            if plan.combination == .fallback, !fragments.isEmpty { break }
        }
        return fragments
    }

    private static func htmlRoot(_ html: String) throws -> Element {
        let trimmed = html.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if trimmed.hasPrefix("<!doctype") || trimmed.hasPrefix("<html") {
            return try SwiftSoup.parse(html)
        }
        return try SwiftSoup.parseBodyFragment(html).body() ?? SwiftSoup.parseBodyFragment(html)
    }

    /// The element HTML is of: its first element, or the document.
    private static func htmlElement(_ html: String) throws -> Element? {
        let root = try htmlRoot(html)
        if root is Document { return root }
        return root.children().first() ?? root
    }

    static func aes(_ input: Data, key: Data, iv: Data, transformation: String, decrypt: Bool) -> Data? {
        let parts = transformation.uppercased().split(separator: "/").map(String.init)
        guard parts.first == "AES", [16, 24, 32].contains(key.count) else { return nil }
        let mode = parts.count > 1 ? parts[1] : "ECB"
        let padding = parts.count > 2 ? parts[2] : "PKCS5PADDING"
        var options = CCOptions(0)
        if mode == "ECB" { options |= CCOptions(kCCOptionECBMode) } else if mode != "CBC" { return nil }
        if padding != "NOPADDING" { options |= CCOptions(kCCOptionPKCS7Padding) }
        let vector = mode == "CBC" ? (iv.count >= kCCBlockSizeAES128 ? iv.prefix(kCCBlockSizeAES128) : iv + Data(count: kCCBlockSizeAES128 - iv.count)) : Data()
        var output = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
        let capacity = output.count
        var written = 0
        let status = key.withUnsafeBytes { keyBytes in
            vector.withUnsafeBytes { ivBytes in
                input.withUnsafeBytes { inputBytes in
                    CCCrypt(decrypt ? CCOperation(kCCDecrypt) : CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), options,
                            keyBytes.baseAddress, key.count, mode == "CBC" ? ivBytes.baseAddress : nil,
                            inputBytes.baseAddress, input.count, &output, capacity, &written)
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(output.prefix(written))
    }

    private static let androidClassesBootstrap = #"""
        (function (global) {
          function LegadoElement(html) {
            if (!(this instanceof LegadoElement)) return new LegadoElement(html);
            this.__html = String(html == null ? '' : html);
          }
          function elements(list) {
            var items = (list || []).map(function (html) { return new LegadoElement(html); });
            items.text = function () { return items.map(function (e) { return e.text(); }).join(' '); };
            items.html = function () { return items.map(function (e) { return e.html(); }).join('\n'); };
            items.outerHtml = function () { return items.map(function (e) { return e.outerHtml(); }).join('\n'); };
            items.attr = function (name) {
              for (var i = 0; i < items.length; i++) { var v = items[i].attr(name); if (v) return v; }
              return '';
            };
            items.eachText = function () { return items.map(function (e) { return e.text(); }); };
            items.eachAttr = function (name) { return items.map(function (e) { return e.attr(name); }); };
            items.select = function (css) {
              return elements([].concat.apply([], items.map(function (e) { return __legadoHTMLSelect(e.__html, String(css)); })));
            };
            items.first = function () { return items.length ? items[0] : null; };
            items.last = function () { return items.length ? items[items.length - 1] : null; };
            items.get = function (index) { return items[index]; };
            items.size = function () { return items.length; };
            items.isEmpty = function () { return items.length === 0; };
            items.toString = items.outerHtml;
            return items;
          }
          LegadoElement.prototype = {
            text: function () { return __legadoHTMLText(this.__html); },
            ownText: function () { return __legadoHTMLOwnText(this.__html); },
            html: function () { return __legadoHTMLInner(this.__html); },
            outerHtml: function () { return this.__html; },
            attr: function (name) { return __legadoHTMLAttr(this.__html, String(name)); },
            hasAttr: function (name) { return this.attr(name) !== ''; },
            tagName: function () { return __legadoHTMLTagName(this.__html); },
            select: function (css) { return elements(__legadoHTMLSelect(this.__html, String(css))); },
            selectFirst: function (css) { return this.select(css).first(); },
            children: function () { return elements(__legadoHTMLChildren(this.__html)); },
            child: function (index) { return this.children()[index] || null; },
            getElementsByTag: function (tag) { return this.select(String(tag)); },
            getElementsByClass: function (name) { return this.select('.' + String(name).trim().split(/\s+/).join('.')); },
            getElementById: function (id) { return this.select('#' + String(id)).first(); },
            body: function () { return this.selectFirst('body') || this; },
            toString: function () { return this.__html; }
          };
          global.__legadoElement = LegadoElement;
          global.__legadoElementsOf = elements;
          var Jsoup = {
            parse: function (html) { return new LegadoElement(String(html)); },
            parseBodyFragment: function (html) { return new LegadoElement(String(html)); }
          };
          Object.defineProperty(Jsoup, '__javaSimpleName', { value: 'Jsoup' });
          global.__legadoJsoup = Object.freeze(Jsoup);
          var JavaThread = { sleep: function (ms) { __legadoSleep(Number(ms) || 0); } };
          Object.defineProperty(JavaThread, '__javaSimpleName', { value: 'Thread' });
          global.__legadoThread = Object.freeze(JavaThread);
          function HashMap() {
            if (!(this instanceof HashMap)) return new HashMap();
            Object.defineProperty(this, '__map', { value: {} });
          }
          HashMap.prototype = {
            put: function (k, v) { var old = this.__map[k]; this.__map[String(k)] = v; return old === undefined ? null : old; },
            get: function (k) { var v = this.__map[String(k)]; return v === undefined ? null : v; },
            containsKey: function (k) { return Object.prototype.hasOwnProperty.call(this.__map, String(k)); },
            remove: function (k) { var v = this.get(k); delete this.__map[String(k)]; return v; },
            keySet: function () { return Object.keys(this.__map); },
            size: function () { return Object.keys(this.__map).length; },
            isEmpty: function () { return this.size() === 0; },
            toString: function () { return JSON.stringify(this.__map); }
          };
          Object.defineProperty(HashMap, '__javaSimpleName', { value: 'HashMap' });
          global.__legadoHashMap = HashMap;
          function ArrayList() {
            if (!(this instanceof ArrayList)) return new ArrayList();
            var list = [];
            list.add = function (v) { list.push(v); return true; };
            list.get = function (i) { return list[i]; };
            list.size = function () { return list.length; };
            list.isEmpty = function () { return list.length === 0; };
            return list;
          }
          Object.defineProperty(ArrayList, '__javaSimpleName', { value: 'ArrayList' });
          global.__legadoArrayList = ArrayList;
        })(this);
        """#

    private static let androidAPIsBootstrap = #"""
        (function (global) {
          var java = global.java;
          if (java) {
            java.getElements = function (rule, content) {
              return __legadoElementsOf(__legadoElements(String(rule == null ? '' : rule), arguments.length < 2 || content == null ? src : String(content)));
            };
            java.getElement = function (rule, content) {
              var found = java.getElements.apply(java, arguments);
              return found.length ? found[0] : null;
            };
            java.getStringList = function (rule, content, isUrl) {
              return __legadoStringList(String(rule == null ? '' : rule), arguments.length < 2 || content == null ? src : content, Boolean(isUrl));
            };
            java.setContent = function (content) { src = content; return content; };
            java.t2s = function (text) { return __legadoChinese(String(text == null ? '' : text), true); };
            java.s2t = function (text) { return __legadoChinese(String(text == null ? '' : text), false); };
            function aes(data, key, transformation, iv, decrypt) {
              return __legadoAES(data, String(key), String(transformation || 'AES/ECB/PKCS5Padding'), String(iv || ''), decrypt, false);
            }
            function bytesOrNull(value) { if (!Array.isArray(value)) throw new Error('AES operation failed'); return value; }
            java.aesBase64DecodeToString = function (data, key, transformation, iv) {
              return __legadoUTF8String(bytesOrNull(aes(__legadoBase64DecodeBytes(String(data)), key, transformation, iv, true)));
            };
            java.aesBase64DecodeToByteArray = function (data, key, transformation, iv) {
              return bytesOrNull(aes(__legadoBase64DecodeBytes(String(data)), key, transformation, iv, true));
            };
            java.aesDecodeToString = function (data, key, transformation, iv) {
              return __legadoUTF8String(bytesOrNull(aes(__legadoUTF8Bytes(String(data)), key, transformation, iv, true)));
            };
            java.aesEncodeToBase64String = function (data, key, transformation, iv) {
              return __legadoBase64EncodeBytes(bytesOrNull(aes(__legadoUTF8Bytes(String(data)), key, transformation, iv, false)));
            };
            java.aesEncodeToString = java.aesEncodeToBase64String;
            java.cacheFile = function (url, saveTime) {
              var key = 'file:' + String(url);
              var cached = __legadoCacheGet(key);
              if (cached != null) return cached;
              var body = java.ajax(String(url));
              if (body) __legadoCachePut(key, body, Number(saveTime) || 0);
              return body;
            };
            java.lang = java.lang || Packages.java.lang;
            java.util = java.util || Packages.java.util;
            java.net = java.net || Packages.java.net;
          }
          if (typeof source !== 'undefined' && source) {
            source.getVariable = function () { return __legadoSourceVariable(); };
            source.setVariable = function (value) { __legadoSetSourceVariable(value); };
            source.getLoginHeaderMap = function () {
              var map = __legadoLoginHeaders() || {};
              map.get = function (key) { return map[String(key)]; };
              return map;
            };
          }
          global.cache = {
            get: function (key) { var v = __legadoCacheGet(String(key)); return v == null ? null : v; },
            put: function (key, value, saveTime) { __legadoCachePut(String(key), value, Number(saveTime) || 0); },
            delete: function (key) { __legadoCachePut(String(key), '', -1); },
            getFromMemory: function (key) { return global.cache.get(key); },
            putMemory: function (key, value) { global.cache.put(key, value, 0); },
            getFile: function (key) { return global.cache.get(key); },
            putFile: function (key, value, saveTime) { global.cache.put(key, value, saveTime); }
          };
          if (typeof global.org === 'undefined') global.org = Packages.org;
          if (typeof global.importClass === 'undefined') {
            global.importClass = function () {
              for (var i = 0; i < arguments.length; i++) {
                var value = arguments[i];
                if (value && typeof value.__javaSimpleName === 'string') global[value.__javaSimpleName] = value;
              }
            };
          }
          if (typeof global.importPackage === 'undefined') {
            global.importPackage = function () {
              for (var i = 0; i < arguments.length; i++) {
                var value = arguments[i] || {};
                Object.keys(value).forEach(function (name) {
                  if (value[name] && typeof value[name].__javaSimpleName === 'string') global[name] = value[name];
                });
              }
            };
          }
        })(this);
        """#
}
