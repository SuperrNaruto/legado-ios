import Foundation
import Testing
@testable import LegadoCore

/// What Legado's scripts reach on Android: Jsoup, a few Java classes, and helpers on
/// `java`, `source` and `cache`.
struct JavaScriptAndroidCompatibilityTests {
    private let page = """
        <html><body><ul id="list">
          <li class="book new"><a href="/b/1" title="One">第一本</a></li>
          <li class="book"><a href="/b/2" title="Two">第二本</a></li>
        </ul></body></html>
        """

    private func run(_ script: String, source: BookSource? = nil, result: JSONValue = .null) throws -> String {
        try JavaScriptRuleEvaluator().evaluate(
            script: script,
            result: result,
            executionContext: .init(source: source)
        ).value.stringValue
    }

    @Test func jsoupParsesAndSelects() throws {
        let script = """
            var doc = org.jsoup.Jsoup.parse(result);
            var items = doc.select('li.book');
            [items.size(), items.first().select('a').attr('href'), items.get(1).text(),
             doc.getElementsByClass('book new').first().selectFirst('a').attr('title'),
             doc.select('a').eachText().join('|')].join(',')
            """
        #expect(try run(script, result: .string(page)) == "2,/b/1,第二本,One,第一本|第二本")
    }

    @Test func javaElementsAreJsoupElements() throws {
        let script = """
            var books = java.getElements('class.book', result);
            var first = java.getElement('id.list@tag.a', result);
            books.length + ':' + books[1].select('a').text() + ':' + first.attr('title') + ':' + first.outerHtml().indexOf('<a')
            """
        #expect(try run(script, result: .string(page)) == "2:第二本:One:0")
    }

    @Test func htmlTextActsAsJsoupElements() throws {
        let list: JSONValue = .array([.string(#"<li><a href="/1">一</a></li>"#), .string(#"<li><a href="/2">二</a></li>"#)])
        let script = "$[1].text() + '|' + result.select('a').attr('href') + '|' + result.text() + '|' + result[0].length + '|' + result.size()"
        #expect(try run(script, result: list) == "二|/1|一 二|\(#"<li><a href="/1">一</a></li>"#.count)|2")
        // still text where scripts treat it so
        #expect(try run("result.replace('一', '壹').split('>').length", result: .string("<b>一</b>")) == "3")
    }

    @Test func stringListsAreEachValue() throws {
        let script = "java.getStringList('class.book@tag.a@text', result).join('|') + ';' + java.getStringList('$.n', '{\"n\":[1,2]}').length"
        #expect(try run(script, result: .string(page)) == "第一本|第二本;2")
    }

    @Test func setContentIsWhatGetStringReads() throws {
        #expect(try run("java.setContent('<p class=\"x\">set</p>'); java.getString('class.x@text')") == "set")
    }

    @Test func chineseConverts() throws {
        #expect(try run("java.t2s('這個書簡體') + '|' + java.s2t('这个书')") == "这个书简体|這個書")
    }

    @Test func aesRoundTrips() throws {
        let key = "0123456789abcdef"
        for transformation in ["AES/CBC/PKCS5Padding", "AES/ECB/PKCS5Padding"] {
            let script = """
                var e = java.aesEncodeToBase64String('第一段正文', '\(key)', '\(transformation)', 'fedcba9876543210');
                java.aesBase64DecodeToString(e, '\(key)', '\(transformation)', 'fedcba9876543210')
                """
            #expect(try run(script) == "第一段正文")
        }
    }

    @Test func aesMatchesAKnownCipherText() throws {
        // OpenSSL: echo -n 'hello' | openssl enc -aes-128-ecb -K 30313233343536373839616263646566 | base64
        let script = "java.aesBase64DecodeToString('Z0x+8454yr2c7JwSWCOmOQ==', '0123456789abcdef', 'AES/ECB/PKCS5Padding', '')"
        #expect(try run(script) == "hello")
    }

    @Test func sourceVariablesAndLoginHeadersAreKept() throws {
        let source = BookSource(bookSourceUrl: "https://variable.example.test/\(UUID().uuidString)", bookSourceName: "V")
        _ = try run("source.setVariable('{\"token\":\"t\"}'); source.putLoginHeader('{\"Authorization\":\"Bearer x\"}')", source: source)
        #expect(try run("JSON.parse(source.getVariable()).token + source.getLoginHeaderMap().get('Authorization')", source: source) == "tBearer x")
    }

    @Test func cacheKeepsValuesUntilTheyExpire() throws {
        let key = UUID().uuidString
        #expect(try run("cache.put('\(key)', 'kept', 60); cache.get('\(key)')") == "kept")
        #expect(try run("cache.put('\(key)', 'gone', 60); cache.delete('\(key)'); String(cache.get('\(key)'))") == "null")
    }

    @Test func javaClassesImportAndRun() throws {
        let script = """
            importClass(Packages.java.util.HashMap);
            var map = new HashMap(); map.put('a', 1);
            java.lang.Thread.sleep(1);
            var j = JavaImporter(Packages.org.jsoup);
            with (j) { Jsoup.parse('<b>x</b>').text() + map.get('a') + map.containsKey('b') }
            """
        #expect(try run(script) == "x1false")
    }
}
