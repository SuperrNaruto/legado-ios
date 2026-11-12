import Foundation
import Testing
@testable import LegadoCore

struct RuleEngineTests {
    @Test func scalarResultMatchesLegadoJoinAndLeadingURLSemantics() {
        let result = RuleEvaluation(values: [.string(""), .string("乙"), .string("丙")])
        #expect(result.joinedString == "\n乙\n丙")
        #expect(result.leadingString == nil)
        #expect(result.firstString == "乙")
    }

    private let engine = RuleEngine()

    @Test func javaScriptStagesContinueIntoSelectorsAndReplacementOnlyRules() async {
        let result = await engine.evaluate(
            "<js>result.replace('旧', '新')</js>class.body@text<js>result + ' 广告'</js>## 广告",
            inText: "<div class='body'>旧正文</div>"
        )
        #expect(result.strings == ["新正文"])
        #expect(result.diagnostics.isEmpty)
        let replaced = await engine.evaluate("##广告##", inText: "正文广告")
        #expect(replaced.strings == ["正文"])
        #expect(replaced.diagnostics.isEmpty)
    }

    @Test func aReplacementAfterAnAtJSScriptAppliesToItsResult() async {
        let result = await engine.evaluate(
            "tag.a@href\n@js:result.replace('/go?u=', '')\n##[^/]+//",
            inText: "<a href='/go?u=https://site.test/book/1'>A</a>"
        )
        #expect(result.strings == ["site.test/book/1"])
        #expect(result.diagnostics.isEmpty)
    }

    @Test func listJavaScriptReceivesWholeListAndScalarJavaScriptReceivesJoinedText() async {
        let list = await engine.evaluate(
            "tag.a<js>result.reverse()</js>",
            inText: "<a>A</a><a>B</a>", listMode: true
        )
        #expect(list.diagnostics.isEmpty)
        #expect(list.values.first?[0]?.stringValue.contains(">B<") == true)
        let scalar = await engine.evaluate("tag.p@text@js:result.split('\\n').reverse().join('|')", inText: "<p>A</p><p>B</p>")
        #expect(scalar.strings == ["B|A"])
    }

    @Test func javaScriptCanReadOriginalContentAfterExtractionAndReturnJSON() async {
        let result = await engine.evaluate(
            "tag.h1@text@js:result + ':' + java.getString('tag.p@text')",
            inText: "<h1>书名</h1><p>作者</p>"
        )
        #expect(result.strings == ["书名:作者"])
        let json = await engine.evaluate("<js>JSON.parse(result.slice(4))</js>$.data.name", inText: "data{\"data\":{\"name\":\"书名\"}}")
        #expect(json.strings == ["书名"])
        #expect(json.diagnostics.isEmpty)
    }

    @Test func standaloneDynamicRulesReturnValuesAndJavaScriptIsNotParsedAsRuleSyntax() async {
        let variable = await engine.evaluate("@get:{token}", inText: "<p/>", context: .init(variables: ["token": "abc"]))
        #expect(variable.strings == ["abc"])
        let inline = await engine.evaluate("{{'https://example.test/' + 42}}", inText: "<p/>")
        #expect(inline.strings == ["https://example.test/42"])
        let script = await engine.evaluate("@js:result.replace('##', '')", inText: "正文##")
        #expect(script.strings == ["正文"])
        // Legado splits a script at ## as it does any rule: what follows replaces in its result
        let replaced = await engine.evaluate("<js>result + '广告'</js>", inText: "正文")
        #expect(replaced.strings == ["正文广告"])
        let tagged = await engine.evaluate("<js>result + '广告'##广告</js>", inText: "正文")
        #expect(tagged.strings == ["正文"])
        let nested = await engine.evaluate("{{@CSS:h1@text}}-{{//p/text()}}", inText: "<h1>书名</h1><p>作者</p>")
        #expect(nested.strings == ["书名-作者"])
        let jsonString = await engine.evaluate("<js>result</js>{{$.name}}", inText: #"{"name":"书名"}"#)
        #expect(jsonString.strings == ["书名"])
        let captures = await engine.evaluate("$1##(甲)##$1乙", in: .array([.string("甲"), .string("甲")]))
        #expect(captures.strings == ["甲乙"])
    }

    @Test func importedQQBookURLsAndNumericCoverIDsUseStringPipelineSemantics() async throws {
        let input = try JSONValue.decode(data: Data(#"{"bid":1009704712}"#.utf8))
        let url = await engine.evaluate(
            "$.bid\n<js>1100000000+parseInt(result)</js>\nhttps://bookshelf.html5.qq.com/qbread/api/novel/intro-info?bookid={{result}}",
            in: input
        )
        #expect(url.strings == ["https://bookshelf.html5.qq.com/qbread/api/novel/intro-info?bookid=2109704712"])
        #expect(url.diagnostics.isEmpty)
        let cover = await engine.evaluate("$.bid@js:result.slice(-3)", in: input)
        #expect(cover.strings == ["712"])
        #expect(cover.diagnostics.isEmpty)
        let literal = await engine.evaluate("https://example.test/@get:{id}", in: input, context: .init(variables: ["id": "42"]))
        #expect(literal.strings == ["https://example.test/42"])
    }

    @Test func combinesFallbackAndConcatenation() async throws {
        let input = try JSONValue.decode(data: Data(#"{"a":"A","b":"B"}"#.utf8))

        let fallback = await engine.evaluate("$.missing||$.b", in: input)
        #expect(fallback.strings == ["B"])
        #expect(fallback.diagnostics.isEmpty)

        let concatenated = await engine.evaluate("$.a&&$.b", in: input)
        #expect(concatenated.strings == ["A", "B"])
    }

    @Test func appliesRegexReplacement() async throws {
        let input = try JSONValue.decode(data: Data(#"{"name":"A   B"}"#.utf8))

        let result = await engine.evaluate("$.name##\\s+## ", in: input)

        #expect(result.firstString == "A B")
    }

    @Test func regexCapturesAndRejectsHighRiskPattern() throws {
        let evaluator = RegexEvaluator()
        #expect(try evaluator.captureGroups(pattern: #"(\w+):(\d+)"#, input: "a:1 b:2") == [
            ["a:1", "a", "1"], ["b:2", "b", "2"]
        ])
        #expect(throws: RuleEngineError.self) {
            try evaluator.captureGroups(pattern: "(a+)+", input: String(repeating: "a", count: 100))
        }
    }

    @Test func interleaveStopsAtFirstBranchLength() async throws {
        let input = try JSONValue.decode(data: Data(#"{"a":["A"],"b":["B1","B2"]}"#.utf8))
        let result = await engine.evaluate("$.a[*]%%$.b[*]", in: input)
        #expect(result.strings == ["A", "B1"])
    }

    @Test func replacementUsesFirstMatchAndInvalidRegexFallback() throws {
        let evaluator = RegexEvaluator()

        #expect(try evaluator.replacing(pattern: #"\d+"#, in: "a12b34", with: "<$0>", firstOnly: true) == "<12>")
        #expect(try evaluator.replacing(pattern: #"\d+"#, in: "abc", with: "x", firstOnly: true) == "")
        #expect(try evaluator.replacing(pattern: "[", in: "a[b[", with: "x", firstOnly: false) == "axbx")
        #expect(try evaluator.replacing(pattern: "[", in: "unchanged", with: "fallback", firstOnly: true) == "fallback")
    }

    @Test func supportsPutGetAndInlineJavaScriptInRules() async throws {
        let input = try JSONValue.decode(data: Data(#"{"selector":"field","field":"ok"}"#.utf8))

        let putGet = await engine.evaluate(#"@put:{"selected":"$.selector"}$.@get:{selected}"#, in: input)
        let inline = await engine.evaluate(#"$.{{java.put('inlineUsed','yes'); 'field'}}"#, in: input)

        #expect(putGet.firstString == "ok")
        #expect(putGet.variables["selected"] == "field")
        #expect(inline.firstString == "ok")
        #expect(inline.variables["inlineUsed"] == "yes")
    }

    @Test func unquotedPutRulesPreserveBookIDsAndReturnTheSelectedTitle() async throws {
        let input = try JSONValue.decode(data: Data(#"{"id":42,"title":"书名","selector":"field","field":"正文"}"#.utf8))
        let result = await engine.evaluate("title@put:{bid:id, selected:$.selector}", in: input)
        #expect(result.diagnostics.isEmpty)
        #expect(result.firstString == "书名")
        #expect(result.variables["bid"] == "42")
        #expect(result.variables["selected"] == "field")
        let body = await engine.evaluate("$.@get:{selected}", in: input, context: .init(variables: result.variables))
        #expect(body.firstString == "正文")
        let html = await engine.evaluate("h1@text@put:{chapter:a@href}", inText: "<h1>章节</h1><a href='/1'>目录</a>")
        #expect(html.diagnostics.isEmpty)
        #expect(html.firstString == "章节")
        #expect(html.variables["chapter"] == "/1")
    }

    @Test func dynamicDoubleBracesTreatJSONPathAsNestedRuleInsteadOfJavaScript() async throws {
        let input = try JSONValue.decode(data: Data(#"{"book_id":"42","category":"科幻"}"#.utf8))

        let value = await engine.evaluate(#"{{$.category}}-{{$.book_id}}"#, in: input)
        let piped = await engine.evaluate(#"{{$.category}}@js:result + '-已处理'"#, in: input)

        #expect(value.firstString == "科幻-42")
        #expect(value.diagnostics.isEmpty)
        #expect(piped.firstString == "科幻-已处理")
        #expect(piped.diagnostics.isEmpty)
    }

    @Test func putOnlyRuleKeepsCurrentResultWhileWritingVariable() async throws {
        let input = try JSONValue.decode(data: Data(#"{"name":"保留"}"#.utf8))

        let result = await engine.evaluate(#"@put:{"saved":"$.name"}"#, in: input)

        #expect(result.values == [input])
        #expect(result.variables["saved"] == "保留")
    }

    @Test func allInOneRegexProducesCaptureRowsAndDollarFields() async throws {
        let rows = await engine.evaluate(
            #":name=([^;]+);url=([^\n]+)"#,
            inText: "name=甲;url=/a\nname=乙;url=/b",
            listMode: true
        )
        let first = try #require(rows.values.first)

        let name = await engine.evaluate("$1", in: first)
        let url = await engine.evaluate("$2", in: first)

        #expect(rows.values.count == 2)
        #expect(name.firstString == "甲")
        #expect(url.firstString == "/a")
    }

    @Test func allInOneRegexSupportsSequentialAndChain() async {
        let rows = await engine.evaluate(
            #":<row>.*?</row>&&name=(\w+)"#,
            inText: "<row>name=first</row><skip>x</skip><row>name=second</row>",
            listMode: true
        )

        #expect(rows.values.count == 2)
        #expect(rows.values[0][1]?.stringValue == "first")
        #expect(rows.values[1][1]?.stringValue == "second")
    }
}
