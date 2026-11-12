import Testing
@testable import LegadoCore

struct HTMLRuleEvaluatorTests {
    private let evaluator = HTMLRuleEvaluator()
    private let html = """
    <!doctype html><html><body>
      <ul id="books">
        <li class="book"><a href="/a"><span class="title">A &amp; One</span></a><p>Intro <b>A</b></p></li>
        <li class="book"><a href="/b"><span class="title">B</span></a><p>Intro B</p></li>
      </ul>
    </body></html>
    """

    @Test func legacyListChainsPreserveTableRowsAndCurrentElementOutputs() throws {
        let page = "<table class='grid'><tr><th>书名</th></tr><tr data-id='42'><td><a href='/42'>测试书</a></td><td>作者</td></tr></table>"
        let rows = try evaluator.selectCSSFragments("class.grid@tag.tr!0", html: page)
        #expect(rows.count == 1)
        let row = try #require(rows.first)
        #expect(try evaluator.extractCSS("tag.td.0@text", html: row, isFragment: true) == ["测试书"])
        #expect(try evaluator.extractCSS("data-id", html: row, isFragment: true) == ["42"])
        let links = try evaluator.selectCSSFragments("tag.a", html: row, isFragment: true)
        let link = try #require(links.first)
        #expect(try evaluator.extractCSS("text", html: link, isFragment: true) == ["测试书"])
        #expect(try evaluator.extractCSS("href", html: link, isFragment: true) == ["/42"])
        #expect(try evaluator.extractXPath("./@href", html: link, isFragment: true) == ["/42"])
        #expect(try evaluator.extractXPath("./text()", html: link, isFragment: true) == ["测试书"])
    }

    @Test func selectsCSSFragmentsAndExtractsOutputs() throws {
        let fragments = try evaluator.selectCSSFragments("li.book", html: html)

        #expect(fragments.count == 2)
        #expect(try evaluator.extractCSS(".title@text", html: fragments[0]) == ["A & One"])
        #expect(try evaluator.extractCSS("a@href", html: fragments[0]) == ["/a"])
        #expect(try evaluator.extractCSS("p@html", html: fragments[0]) == ["<p>Intro <b>A</b></p>"])
        #expect(try evaluator.extractCSS("a@all", html: fragments[0]).first?.contains("href=\"/a\"") == true)
    }

    @Test func selectsXPathFragmentsAndScalarValues() throws {
        let fragments = try evaluator.selectXPathFragments("//li[@class='book']", html: html)

        #expect(fragments.count == 2)
        #expect(try evaluator.extractXPath("//span[@class='title']/text()", html: fragments[1]) == ["B"])
        #expect(try evaluator.extractXPath("count(//li[@class='book'])", html: html) == ["2"])
    }

    @Test func ruleEngineAppliesHTMLCombination() async {
        let engine = RuleEngine()

        let result = await engine.evaluate("@CSS:.missing@text||@CSS:.title@text", inText: html)

        #expect(result.strings == ["A & One", "B"])
        #expect(result.diagnostics.isEmpty)
    }

    @Test func aClassWithSpacesNamesSeveralClassesOfOneElement() throws {
        let page = #"<div class="comic-list clearfix"><p class="item">A</p><p class="item">B</p></div><div class="comic-list"><p class="item">C</p></div>"#
        #expect(try evaluator.extractCSS("class.comic-list clearfix@class.item@text", html: page) == ["A", "B"])
    }

    @Test func supportsLegadoChainAndIndexedSelectors() throws {
        #expect(try evaluator.extractCSS("id.books@tag.li[1]@class.title@text", html: html) == ["B"])
        #expect(try evaluator.extractCSS("li.book[-1:0]@class.title@text", html: html) == ["B", "A & One"])
        #expect(try evaluator.extractCSS("li.book[!0]@class.title@text", html: html) == ["B"])
    }

    @Test func supportsLegacyOutputOnlyRulesOnCurrentDocument() throws {
        #expect(try evaluator.extractCSS("@text", html: "<main><b>正文</b></main>") == ["正文"])
        #expect(try evaluator.extractCSS("@html", html: "<main><b>正文</b></main>").first?.contains("<main>") == true)
        #expect(try evaluator.extractCSS("meta@content", html: "<!doctype html><html><head><meta content='书名'></head><body>正文</body></html>", isFragment: true) == ["书名"])
    }

    @Test func reportsSwiftSoupSelectorMessageInsteadOfOpaqueNSError() throws {
        do {
            _ = try evaluator.extractCSS("div[", html: html)
            Issue.record("应拒绝未闭合的 CSS selector")
        } catch let error as RuleEngineError {
            #expect(!error.localizedDescription.contains("SwiftSoup.Exception error 0"))
            #expect(error.localizedDescription.contains("CSS 规则执行失败"))
        }
    }

    @Test func supportsLegacyDiscreteNegativeIndexes() throws {
        #expect(try evaluator.extractCSS("tag.li.-1:0@class.title@text", html: html) == ["B", "A & One"])
        #expect(try evaluator.selectCSSFragments("li.book[-1]", html: html).count == 1)
    }

    @Test func htmlAndAllCombineOuterHTMLAndDeduplicateAttributes() throws {
        let value = """
        <div class="item"><script>bad()</script><span>A</span></div>
        <div class="item"><style>.bad{}</style><span>B</span></div>
        <a class="same" href="/same">one</a><a class="same" href="/same">two</a>
        """

        let sanitized = try evaluator.extractCSS(".item@html", html: value)
        let all = try evaluator.extractCSS(".item@all", html: value)
        let links = try evaluator.extractCSS("a.same@href", html: value)

        #expect(sanitized.count == 1)
        #expect(sanitized[0].contains("<div class=\"item\">") == true)
        #expect(sanitized[0].contains("script") == false)
        #expect(sanitized[0].contains("style") == false)
        #expect(all.count == 1)
        #expect(links == ["/same"])
    }

    @Test func negativeRangeStepUsesListLengthAdjustment() throws {
        let value = "<p>0</p><p>1</p><p>2</p><p>3</p><p>4</p>"

        #expect(try evaluator.extractCSS("p[0:4:-2]@text", html: value) == ["0", "3"])
    }

    @Test func rangeWhollyOutsideOneSideIsIgnoredInsteadOfClamped() throws {
        let value = "<p>0</p><p>1</p><p>2</p>"

        #expect(try evaluator.extractCSS("p[8:9]@text", html: value).isEmpty)
        #expect(try evaluator.extractCSS("p[-9:-8]@text", html: value).isEmpty)
        #expect(try evaluator.extractCSS("p[-9:1]@text", html: value) == ["0", "1"])
    }
}
