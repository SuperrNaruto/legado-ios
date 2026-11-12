import Foundation

public struct RuleEngine: Sendable {
    private let parser: RuleExpressionParser
    private let jsonPath: JSONPathEvaluator
    private let regex: RegexEvaluator
    private let html: HTMLRuleEvaluator
    private let javaScript: JavaScriptRuleEvaluator

    public init(
        parser: RuleExpressionParser = .init(),
        jsonPath: JSONPathEvaluator = .init(),
        regex: RegexEvaluator = .init(),
        html: HTMLRuleEvaluator = .init(),
        javaScript: JavaScriptRuleEvaluator = .init()
    ) {
        self.parser = parser
        self.jsonPath = jsonPath
        self.regex = regex
        self.html = html
        self.javaScript = javaScript
    }

    public func evaluate(
        _ rule: String,
        in input: JSONValue,
        listMode: Bool = false,
        context: RuleExecutionContext = .init()
    ) async -> RuleEvaluation {
        var context = context
        if context.content == nil { context.content = input }
        if let pipeline = splitJavaScriptPipeline(rule) {
            return await evaluatePipeline(pipeline, input: input, listMode: listMode, context: context)
        }
        do {
            let extracted = try extractPutRules(rule)
            if !extracted.puts.isEmpty {
                var nextContext = context
                var diagnostics: [RuleDiagnostic] = []
                for key in extracted.puts.keys.sorted() {
                    guard let valueRule = extracted.puts[key] else { continue }
                    let value = await evaluate(valueRule, in: input, context: nextContext)
                    diagnostics += value.diagnostics
                    nextContext.variables.merge(value.variables) { _, new in new }
                    nextContext.variables[key] = value.strings.joined(separator: "\n")
                }
                if extracted.rule.isEmpty {
                    return .init(values: [input], diagnostics: diagnostics, variables: nextContext.variables)
                }
                var result = await evaluate(extracted.rule, in: input, listMode: listMode, context: nextContext)
                result.diagnostics = diagnostics + result.diagnostics
                result.variables = nextContext.variables.merging(result.variables) { _, new in new }
                return result
            }
            let rendered = try await renderDynamicRule(extracted.rule, result: input, context: context)
            if rendered.captureLiteral {
                return literalEvaluation(rendered.rule, context: rendered.context)
            }
            if rendered.context.variables != context.variables {
                var result = await evaluatePrepared(rendered.rule, in: input, listMode: listMode, context: rendered.context)
                result.variables = rendered.context.variables.merging(result.variables) { _, new in new }
                return result
            }
            return await evaluatePrepared(rendered.rule, in: input, listMode: listMode, context: rendered.context)
        } catch let error as RuleEngineError {
            return .init(diagnostics: [error.diagnostic], variables: context.variables)
        } catch {
            return .init(diagnostics: [.init(severity: .error, code: "rule.unexpected", message: error.localizedDescription, rule: rule)], variables: context.variables)
        }
    }

    private func evaluatePrepared(
        _ rule: String,
        in input: JSONValue,
        listMode: Bool,
        context: RuleExecutionContext
    ) async -> RuleEvaluation {
        do {
            let plan = try parser.parse(rule, inputLooksLikeJSON: true)
            var results: [[JSONValue]] = []
            var diagnostics: [RuleDiagnostic] = []
            for branch in plan.branches {
                do {
                    var values = try await evaluate(branch, in: input, context: context)
                    if plan.combination == .fallback, isEmpty(values, listMode: listMode) { values = [] }
                    results.append(values)
                    if plan.combination == .fallback, !values.isEmpty { break }
                } catch let error as RuleEngineError {
                    diagnostics.append(error.diagnostic)
                    results.append([])
                } catch {
                    diagnostics.append(.init(
                        severity: .error,
                        code: "rule.unexpected",
                        message: error.localizedDescription,
                        rule: branch.expression
                    ))
                    results.append([])
                }
            }
            return .init(
                values: try applyingReplacement(to: combine(results, with: plan.combination), plan: plan, listMode: listMode),
                diagnostics: diagnostics,
                variables: context.variables
            )
        } catch let error as RuleEngineError {
            return .init(diagnostics: [error.diagnostic], variables: context.variables)
        } catch {
            return .init(diagnostics: [.init(
                severity: .error,
                code: "rule.unexpected",
                message: error.localizedDescription,
                rule: rule
            )], variables: context.variables)
        }
    }

    public func evaluateJSONPath(_ rule: String, in input: JSONValue) throws -> [JSONValue] {
        try jsonPath.evaluate(path: rule, in: input)
    }

    public func evaluate(
        _ rule: String,
        inText input: String,
        baseURL: String = "",
        listMode: Bool = false,
        context: RuleExecutionContext = .init()
    ) async -> RuleEvaluation {
        var context = context
        if context.baseURL.isEmpty { context.baseURL = baseURL }
        if context.content == nil { context.content = .string(input) }
        if let pipeline = splitJavaScriptPipeline(rule) {
            return await evaluatePipeline(pipeline, input: .string(input), listMode: listMode, context: context)
        }
        do {
            let extracted = try extractPutRules(rule)
            if !extracted.puts.isEmpty {
                var nextContext = context
                var diagnostics: [RuleDiagnostic] = []
                for key in extracted.puts.keys.sorted() {
                    guard let valueRule = extracted.puts[key] else { continue }
                    let value = await evaluate(valueRule, inText: input, baseURL: baseURL, listMode: false, context: nextContext)
                    diagnostics += value.diagnostics
                    nextContext.variables.merge(value.variables) { _, new in new }
                    nextContext.variables[key] = value.strings.joined(separator: "\n")
                }
                if extracted.rule.isEmpty {
                    return .init(values: [.string(input)], diagnostics: diagnostics, variables: nextContext.variables)
                }
                var result = await evaluate(extracted.rule, inText: input, baseURL: baseURL, listMode: listMode, context: nextContext)
                result.diagnostics = diagnostics + result.diagnostics
                result.variables = nextContext.variables.merging(result.variables) { _, new in new }
                return result
            }
            let rendered = try await renderDynamicRule(extracted.rule, result: .string(input), context: context)
            if rendered.captureLiteral {
                return literalEvaluation(rendered.rule, context: rendered.context)
            }
            if rendered.context.variables != context.variables {
                var result = await evaluatePrepared(rendered.rule, inText: input, baseURL: baseURL, listMode: listMode, context: rendered.context)
                result.variables = rendered.context.variables.merging(result.variables) { _, new in new }
                return result
            }
            return await evaluatePrepared(rendered.rule, inText: input, baseURL: baseURL, listMode: listMode, context: rendered.context)
        } catch let error as RuleEngineError {
            return .init(diagnostics: [error.diagnostic], variables: context.variables)
        } catch {
            return .init(diagnostics: [.init(severity: .error, code: "rule.unexpected", message: error.localizedDescription, rule: rule)], variables: context.variables)
        }
    }

    private func evaluatePrepared(
        _ rule: String,
        inText input: String,
        baseURL: String,
        listMode: Bool,
        context: RuleExecutionContext
    ) async -> RuleEvaluation {
        if let root = try? JSONValue.decode(data: Data(input.utf8)),
           let plan = try? parser.parse(rule, inputLooksLikeJSON: true),
           plan.branches.allSatisfy({ $0.mode == .jsonPath }) {
            return await evaluatePrepared(rule, in: root, listMode: listMode, context: context)
        }
        if rule.hasPrefix(":"), rule.count > 1 {
            do {
                let patterns = rule.dropFirst().components(separatedBy: "&&").filter { !$0.isEmpty }
                guard !patterns.isEmpty else { return .init(variables: context.variables) }
                var stage = input
                var captures: [[String]] = []
                for (index, pattern) in patterns.enumerated() {
                    captures = try regex.captureGroups(pattern: pattern, input: stage)
                    if index + 1 < patterns.count {
                        stage = captures.compactMap(\.first).joined()
                    }
                }
                return .init(
                    values: captures.map { .array($0.map(JSONValue.string)) },
                    variables: context.variables
                )
            } catch let error as RuleEngineError {
                return .init(diagnostics: [error.diagnostic], variables: context.variables)
            } catch {
                return .init(diagnostics: [.init(severity: .error, code: "rule.unexpected", message: error.localizedDescription, rule: rule)], variables: context.variables)
            }
        }
        do {
            let plan = try parser.parse(rule, inputLooksLikeJSON: (try? JSONValue.decode(data: Data(input.utf8))) != nil)
            var results: [[JSONValue]] = []
            var diagnostics: [RuleDiagnostic] = []
            for branch in plan.branches {
                do {
                    let strings = try await evaluateTextBranch(
                        branch,
                        input: input,
                        baseURL: baseURL,
                        listMode: listMode,
                        context: context
                    )
                    results.append(strings.map(JSONValue.string))
                    if plan.combination == .fallback, !strings.isEmpty { break }
                } catch let error as RuleEngineError {
                    diagnostics.append(error.diagnostic)
                    results.append([])
                }
            }
            return .init(
                values: try applyingReplacement(to: combine(results, with: plan.combination), plan: plan, listMode: listMode),
                diagnostics: diagnostics,
                variables: context.variables
            )
        } catch let error as RuleEngineError {
            return .init(diagnostics: [error.diagnostic], variables: context.variables)
        } catch {
            return .init(diagnostics: [.init(
                severity: .error,
                code: "rule.unexpected",
                message: error.localizedDescription,
                rule: rule
            )], variables: context.variables)
        }
    }

    private func evaluate(
        _ branch: RuleBranch,
        in input: JSONValue,
        context: RuleExecutionContext
    ) async throws -> [JSONValue] {
        try Task.checkCancellation()
        let rawValues: [JSONValue]
        if branch.expression.isEmpty {
            return [input]
        }
        switch branch.mode {
        case .jsonPath:
            rawValues = try jsonPath.evaluateRule(branch.expression, in: input)
        case .regex:
            let matches = try regex.captureGroups(pattern: branch.expression, input: input.stringValue)
            rawValues = matches.map { .array($0.map(JSONValue.string)) }
        case .css:
            throw RuleEngineError.unsupportedRule(rule: branch.expression, feature: "CSS selector")
        case .xpath:
            throw RuleEngineError.unsupportedRule(rule: branch.expression, feature: "XPath")
        case .javaScript:
            rawValues = [try await javaScript.evaluateAsync(
                script: branch.expression,
                result: input,
                executionContext: context
            ).value]
        case .webJavaScript:
            throw RuleEngineError.unsupportedRule(rule: branch.expression, feature: "WKWebView JavaScript")
        }
        return rawValues
    }

    private func evaluateTextBranch(
        _ branch: RuleBranch,
        input: String,
        baseURL: String,
        listMode: Bool,
        context: RuleExecutionContext
    ) async throws -> [String] {
        try Task.checkCancellation()
        let raw: [String]
        if branch.expression.isEmpty {
            return [input]
        }
        switch branch.mode {
        case .css:
            raw = try listMode
                ? html.selectCSSFragments(branch.expression, html: input, baseURL: baseURL, isFragment: context.isHTMLFragment)
                : html.extractCSS(branch.expression, html: input, baseURL: baseURL, isFragment: context.isHTMLFragment)
        case .xpath:
            raw = try listMode
                ? html.selectXPathFragments(branch.expression, html: input, isFragment: context.isHTMLFragment)
                : html.extractXPath(branch.expression, html: input, isFragment: context.isHTMLFragment)
        case .jsonPath:
            let root: JSONValue
            do {
                root = try JSONValue.decode(data: Data(input.utf8))
            } catch {
                throw RuleEngineError.invalidInput(rule: branch.expression, expected: "JSON")
            }
            raw = try jsonPath.evaluateRule(branch.expression, in: root).map(\.stringValue)
        case .regex:
            raw = try regex.captureGroups(pattern: branch.expression, input: input).map { captures in
                captures.count > 1 ? captures.dropFirst().joined() : captures.first ?? ""
            }
        case .javaScript:
            raw = [try await javaScript.evaluateAsync(
                script: branch.expression,
                result: .string(input),
                executionContext: context
            ).value.stringValue]
        case .webJavaScript:
            throw RuleEngineError.unsupportedRule(rule: branch.expression, feature: "WKWebView JavaScript")
        }
        return raw
    }

    private func isEmpty(_ values: [JSONValue], listMode: Bool) -> Bool {
        let result = RuleEvaluation(values: values)
        return listMode
            ? result.listItems(rule: "").filter { $0 != .null }.isEmpty
            : result.strings.joined(separator: "\n").isEmpty
    }

    private func applyingReplacement(to values: [JSONValue], plan: RulePlan, listMode: Bool) throws -> [JSONValue] {
        guard let branch = plan.branches.first, let pattern = branch.replacePattern, !pattern.isEmpty else { return values }
        let strings = RuleEvaluation(values: values).strings
        let inputs = listMode ? strings : [strings.joined(separator: "\n")]
        return try inputs.map {
            .string(try regex.replacing(pattern: pattern, in: $0, with: branch.replacement, firstOnly: branch.replaceFirst))
        }
    }

    private func combine(_ results: [[JSONValue]], with combination: RuleCombination) -> [JSONValue] {
        switch combination {
        case .single, .concatenate:
            return results.flatMap { $0 }
        case .fallback:
            return results.first(where: { !$0.isEmpty }) ?? []
        case .interleave:
            guard let firstCount = results.first?.count else { return [] }
            return (0 ..< firstCount).flatMap { index in
                results.compactMap { $0.indices.contains(index) ? $0[index] : nil }
            }
        }
    }

    private func evaluatePipeline(
        _ pipeline: JavaScriptPipeline,
        input: JSONValue,
        listMode: Bool,
        context: RuleExecutionContext
    ) async -> RuleEvaluation {
        var execution = context
        let initial: RuleEvaluation
        if pipeline.prefix.isEmpty {
            initial = .init(values: [input], variables: context.variables)
        } else {
            initial = await evaluateValue(pipeline.prefix, input: input, listMode: listMode, context: context)
        }
        execution.variables = initial.variables
        var diagnostics = initial.diagnostics
        let scriptInput: JSONValue
        if pipeline.prefix.isEmpty {
            scriptInput = input
        } else if listMode {
            if initial.values.count == 1, case .array = initial.values[0] {
                scriptInput = initial.values[0]
            } else {
                scriptInput = .array(initial.values)
            }
        } else {
            scriptInput = .string(initial.strings.joined(separator: "\n"))
        }
        do {
            let rendered = try await renderDynamicRule(pipeline.script, result: scriptInput, context: execution)
            let result = try await javaScript.evaluateAsync(
                script: rendered.rule, result: scriptInput, executionContext: rendered.context
            )
            execution.variables = result.variables
            guard !pipeline.suffix.isEmpty else {
                return .init(values: result.value == .null ? [] : [result.value], diagnostics: diagnostics, variables: execution.variables)
            }
            execution.isHTMLFragment = false
            var next = await evaluateValue(pipeline.suffix, input: result.value, listMode: listMode, context: execution)
            next.diagnostics = diagnostics + next.diagnostics
            return next
        } catch let error as RuleEngineError {
            diagnostics.append(error.diagnostic)
        } catch {
            diagnostics.append(.init(severity: .error, code: "rule.javascript", message: error.localizedDescription, rule: pipeline.script))
        }
        return .init(diagnostics: diagnostics, variables: execution.variables)
    }

    private func evaluateValue(_ rule: String, input: JSONValue, listMode: Bool, context: RuleExecutionContext) async -> RuleEvaluation {
        if case .string(let text) = input {
            return await evaluate(rule, inText: text, baseURL: context.baseURL, listMode: listMode, context: context)
        }
        return await evaluate(rule, in: input, listMode: listMode, context: context)
    }

    private func splitJavaScriptPipeline(_ rule: String) -> JavaScriptPipeline? {
        guard let pattern = try? NSRegularExpression(pattern: #"<js>([\s\S]*?)</js>|@js:([\s\S]*)"#, options: .caseInsensitive),
              let match = pattern.firstMatch(in: rule, range: NSRange(rule.startIndex..., in: rule)),
              let full = Range(match.range, in: rule),
              let script = Range(match.range(at: match.range(at: 2).location == NSNotFound ? 1 : 2), in: rule) else { return nil }
        var body = String(rule[script])
        var suffix = String(rule[full.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
        // As on Legado (AnalyzeRule.SourceRule.makeUpRule splits every segment, scripts
        // included, at `##`), a `##` replacement applies to the script's result. One inside
        // a string literal is left to the script, which Legado would split too, but rules
        // passed to java.getString read well that way.
        if let replacement = Self.replacementStart(inScript: body) {
            suffix = String(body[replacement...]) + suffix
            body = String(body[..<replacement])
        }
        return .init(
            prefix: String(rule[..<full.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines),
            script: body,
            suffix: suffix
        )
    }

    /// Where a script's `##` replacement starts: the first `##` outside string literals.
    static func replacementStart(inScript script: String) -> String.Index? {
        var quote: Character?
        var escaped = false
        var index = script.startIndex
        while index < script.endIndex {
            let character = script[index]
            if let open = quote {
                if escaped {
                    escaped = false
                } else if character == "\\" {
                    escaped = true
                } else if character == open {
                    quote = nil
                }
            } else if character == "'" || character == "\"" || character == "`" {
                quote = character
            } else if character == "#", script.index(after: index) < script.endIndex, script[script.index(after: index)] == "#" {
                return index
            }
            index = script.index(after: index)
        }
        return nil
    }

    private func extractPutRules(_ source: String) throws -> (rule: String, puts: [String: String]) {
        let expression = try NSRegularExpression(pattern: #"@put:(\{[^}]+?\})"#, options: .caseInsensitive)
        let matches = expression.matches(in: source, range: NSRange(source.startIndex..., in: source))
        guard !matches.isEmpty else { return (source, [:]) }
        var puts: [String: String] = [:]
        var rule = source
        for match in matches.reversed() {
            guard let fullRange = Range(match.range(at: 0), in: source),
                  let jsonRange = Range(match.range(at: 1), in: source) else { continue }
            if case .object(let object) = try LegadoURLBuilder.decodeLenientJSON(String(source[jsonRange]), quoteUnquotedValues: true) {
                puts.merge(object.mapValues(\.stringValue)) { _, new in new }
            }
            if let currentRange = Range(match.range(at: 0), in: rule) {
                rule.removeSubrange(currentRange)
            } else {
                rule = rule.replacingOccurrences(of: String(source[fullRange]), with: "")
            }
        }
        return (rule.trimmingCharacters(in: .whitespacesAndNewlines), puts)
    }

    private func renderDynamicRule(
        _ source: String,
        result: JSONValue,
        context: RuleExecutionContext
    ) async throws -> (rule: String, context: RuleExecutionContext, captureLiteral: Bool) {
        var source = source
        var captureLiteral = false
        if case .array(let captures) = result {
            let captureExpression = try NSRegularExpression(pattern: #"\$(\d{1,2})"#)
            let captureEnd = source.range(of: "##")?.lowerBound ?? source.endIndex
            let matches = captureExpression.matches(in: source, range: NSRange(source.startIndex..<captureEnd, in: source))
            if !matches.isEmpty {
                captureLiteral = true
                for match in matches.reversed() {
                    guard let fullRange = Range(match.range(at: 0), in: source),
                          let indexRange = Range(match.range(at: 1), in: source),
                          let index = Int(source[indexRange]) else { continue }
                    source.replaceSubrange(fullRange, with: captures.indices.contains(index) ? captures[index].stringValue : "")
                }
            }
        }
        let expression = try NSRegularExpression(
            pattern: #"@get:\{([^}]+?)\}|\{\{([\s\S]*?)\}\}"#,
            options: .caseInsensitive
        )
        let matches = expression.matches(in: source, range: NSRange(source.startIndex..., in: source))
        guard !matches.isEmpty else { return (source, context, captureLiteral) }
        let replacementStart = source.range(of: "##")?.lowerBound ?? source.endIndex
        let selectorTemplate = source.hasPrefix("$.") || source.hasPrefix("$[")
        if !selectorTemplate, let first = matches.first,
           first.range.location < NSRange(source.startIndex..<replacementStart, in: source).length {
            captureLiteral = true
        }
        var nextContext = context
        var output = ""
        var cursor = source.startIndex
        for match in matches {
            guard let fullRange = Range(match.range(at: 0), in: source) else { continue }
            output += source[cursor..<fullRange.lowerBound]
            if match.range(at: 1).location != NSNotFound,
               let keyRange = Range(match.range(at: 1), in: source) {
                let key = String(source[keyRange])
                if key == "bookName", let book = nextContext.book {
                    output += book.name
                } else if key == "title", let chapter = nextContext.chapter {
                    output += chapter.title
                } else {
                    output += nextContext.variables[key] ?? ""
                }
            } else if let scriptRange = Range(match.range(at: 2), in: source) {
                let expression = String(source[scriptRange]).trimmingCharacters(in: .whitespacesAndNewlines)
                if expression.hasPrefix("@") || expression.hasPrefix("$.") || expression.hasPrefix("$[") || expression.hasPrefix("//") {
                    captureLiteral = true
                    let nested = await evaluateValue(expression, input: context.content ?? result, listMode: false, context: nextContext)
                    if let error = nested.diagnostics.first(where: { $0.severity == .error }) {
                        throw RuleEngineError.malformedRule(rule: expression, detail: error.message)
                    }
                    output += nested.strings.joined(separator: "\n")
                    nextContext.variables = nested.variables
                } else {
                    let evaluated = try await javaScript.evaluateAsync(
                        script: expression,
                        result: result,
                        executionContext: nextContext
                    )
                    output += evaluated.value.stringValue
                    nextContext.variables = evaluated.variables
                }
            }
            cursor = fullRange.upperBound
        }
        output += source[cursor...]
        return (output, nextContext, captureLiteral)
    }

    private func literalEvaluation(_ source: String, context: RuleExecutionContext) -> RuleEvaluation {
        let components = source.components(separatedBy: "##")
        var value = components.first ?? ""
        if components.count > 1, !components[1].isEmpty {
            value = (try? regex.replacing(
                pattern: components[1],
                in: value,
                with: components.count > 2 ? components[2] : "",
                firstOnly: components.count > 3
            )) ?? value
        }
        return .init(values: [.string(value)], variables: context.variables)
    }

    private struct JavaScriptPipeline {
        var prefix: String
        var script: String
        var suffix: String
    }
}
