// Package jsanalysis detects bounded JavaScript obfuscation without executing code.
package jsanalysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"malox/internal/rules"
)

const (
	sourceName         = "jsanalysis"
	defaultDecodeDepth = 2
	defaultDecodedSize = 256 * 1024
	defaultReadLimit   = 1024 * 1024
)

// File describes one scanned source file visible to JavaScript analysis.
type File struct {
	Path         string
	SHA256       string
	Type         string
	PackageOwner string
	Size         int64
}

// Options configures one JavaScript analysis pass.
type Options struct {
	Root              string
	Files             []File
	MaxFileSize       int64
	DecodedPayloadDir string
	MaxDecodeDepth    int
	MaxDecodedBytes   int64
}

// Result contains obfuscation findings and non-fatal analysis warnings.
type Result struct {
	Findings []rules.Finding
	Warnings []rules.Warning
}

// Analyze scans JavaScript-like source files for suspicious encoded payload flow.
func Analyze(ctx context.Context, opts Options) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("analyze javascript: %w", err)
	}
	opts = opts.withDefaults()

	result := Result{
		Findings: []rules.Finding{},
		Warnings: []rules.Warning{},
	}
	seen := map[string]struct{}{}
	for _, file := range opts.Files {
		if !isJavaScriptType(file.Type) {
			continue
		}
		data, err := readSourceFile(opts.Root, file.Path, readLimit(opts.MaxFileSize))
		if err != nil {
			result.Warnings = append(result.Warnings, rules.Warning{
				Path:    file.Path,
				Code:    "jsanalysis_read_error",
				Message: err.Error(),
			})
			continue
		}
		pass := analyzer{
			opts:   opts,
			seen:   seen,
			result: &result,
		}
		pass.analyzeSource(ctx, file, data, 0)
	}
	sortResult(&result)
	return result, nil
}

func (opts Options) withDefaults() Options {
	if opts.MaxDecodeDepth <= 0 {
		opts.MaxDecodeDepth = defaultDecodeDepth
	}
	if opts.MaxDecodedBytes <= 0 {
		opts.MaxDecodedBytes = defaultDecodedSize
	}
	return opts
}

type analyzer struct {
	opts   Options
	seen   map[string]struct{}
	result *Result
}

func (a analyzer) analyzeSource(ctx context.Context, file File, data []byte, depth int) {
	if err := ctx.Err(); err != nil {
		a.warn(file.Path, "jsanalysis_context_canceled", err.Error())
		return
	}
	tokens := lex(data)
	env := constants(tokens)

	for _, token := range tokens {
		if token.kind != tokenString {
			continue
		}
		a.recordEncoded(ctx, file, token.value, token.raw, token.raw, token.line, token.column, depth)
	}
	for name, value := range env {
		a.recordEncoded(ctx, file, value.text, value.expr, name, value.line, value.column, depth)
	}
	a.recordConstructorEscape(file, string(data))
	a.recordBracketGlobals(tokens, env, file)
	a.recordSinkFlow(ctx, tokens, env, file, depth)
}

func (a analyzer) recordEncoded(
	ctx context.Context,
	file File,
	value string,
	expression string,
	label string,
	line int,
	column int,
	depth int,
) {
	decoded, ok := decodeSuspiciousString(value, expression)
	if !ok {
		if entropy(value) >= 4.5 && len(value) >= 32 {
			a.addFinding(file, findingInput{
				ruleID:     "jsanalysis:high-entropy-string",
				severity:   rules.SeverityLow,
				summary:    "high-entropy JavaScript string needs review",
				kind:       "high_entropy_string",
				value:      trimEvidence(value),
				expression: label,
				line:       line,
				column:     column,
			})
		}
		return
	}
	a.recordDecoded(ctx, file, decoded, expression, label, line, column, depth, false)
}

func (a analyzer) recordDecoded(
	ctx context.Context,
	file File,
	decoded decodedValue,
	expression string,
	label string,
	line int,
	column int,
	depth int,
	throughSink bool,
) {
	if int64(len(decoded.bytes)) > a.opts.MaxDecodedBytes {
		a.warn(file.Path, "jsanalysis_decode_limit", "decoded payload exceeds configured maximum size")
		return
	}

	sum := sha256.Sum256(decoded.bytes)
	hash := hex.EncodeToString(sum[:])
	if a.opts.DecodedPayloadDir != "" {
		if err := writeDecodedPayload(ctx, a.opts.DecodedPayloadDir, hash, decoded.bytes); err != nil {
			a.warn(file.Path, "jsanalysis_decoded_cache_error", err.Error())
		}
	}

	severity := rules.SeverityMedium
	summary := "encoded JavaScript payload recovered"
	ruleID := "jsanalysis:encoded-payload"
	if throughSink || decoded.classification == "javascript" || decoded.classification == "shell" {
		severity = rules.SeverityHigh
		summary = "encoded payload flows into a dangerous JavaScript sink"
		ruleID = "jsanalysis:encoded-sink-flow"
	}

	a.addFinding(file, findingInput{
		ruleID:         ruleID,
		severity:       severity,
		summary:        summary,
		kind:           "decoded_payload",
		value:          trimEvidence(decoded.text),
		expression:     firstNonEmpty(label, expression),
		decodedSHA256:  hash,
		classification: decoded.classification,
		decoder:        decoded.decoder,
		line:           line,
		column:         column,
	})

	if depth >= a.opts.MaxDecodeDepth || decoded.classification != "javascript" {
		return
	}
	virtual := file
	virtual.Path = file.Path + "#decoded:" + hash[:12] + ".js"
	virtual.SHA256 = hash
	virtual.Size = int64(len(decoded.bytes))
	virtual.Type = "javascript"
	a.analyzeSource(ctx, virtual, decoded.bytes, depth+1)
}

func (a analyzer) recordConstructorEscape(file File, source string) {
	if !strings.Contains(source, ".constructor.constructor") &&
		!strings.Contains(source, `["constructor"]["constructor"]`) &&
		!strings.Contains(source, `['constructor']['constructor']`) {
		return
	}
	a.addFinding(file, findingInput{
		ruleID:   "jsanalysis:constructor-escape",
		severity: rules.SeverityHigh,
		summary:  "constructor chain can recover Function from JavaScript values",
		kind:     "constructor_escape",
	})
}

func (a analyzer) recordBracketGlobals(tokens []token, env map[string]exprValue, file File) {
	for i := 0; i < len(tokens)-3; i++ {
		if tokens[i].kind != tokenIdent || !isGlobalAlias(tokens[i].value) || tokens[i+1].value != "[" {
			continue
		}
		end := findMatching(tokens, i+1)
		if end <= i+1 {
			continue
		}
		prop, ok := evalExpression(tokens[i+2:end], env, 0)
		if !ok || !isSensitiveGlobal(prop.text) {
			continue
		}
		a.addFinding(file, findingInput{
			ruleID:     "jsanalysis:bracket-global-access",
			severity:   rules.SeverityMedium,
			summary:    "computed bracket notation accesses a sensitive JavaScript global",
			kind:       "bracket_global_access",
			value:      prop.text,
			expression: exprText(tokens[i : end+1]),
			line:       tokens[i].line,
			column:     tokens[i].column,
		})
	}
}

func (a analyzer) recordSinkFlow(ctx context.Context, tokens []token, env map[string]exprValue, file File, depth int) {
	for i := 0; i < len(tokens)-2; i++ {
		if tokens[i].kind != tokenIdent || !isSink(tokens[i].value) || tokens[i+1].value != "(" {
			continue
		}
		end := findMatching(tokens, i+1)
		if end <= i+1 {
			continue
		}
		args := splitTopLevel(tokens[i+2:end], ",")
		if len(args) == 0 {
			continue
		}
		value, ok := evalExpression(args[0], env, 0)
		if !ok {
			continue
		}
		if decoded, ok := decodeSuspiciousString(value.text, value.expr); ok {
			a.recordDecoded(ctx, file, decoded, value.expr, exprText(tokens[i:end+1]), tokens[i].line, tokens[i].column, depth, true)
			continue
		}
		if !value.derived && tokens[i].value != "require" && tokens[i].value != "import" {
			continue
		}
		a.addFinding(file, findingInput{
			ruleID:     "jsanalysis:string-sink-flow",
			severity:   rules.SeverityHigh,
			summary:    "derived string flows into a dangerous JavaScript sink",
			kind:       "string_sink_flow",
			value:      trimEvidence(value.text),
			expression: exprText(tokens[i : end+1]),
			line:       tokens[i].line,
			column:     tokens[i].column,
		})
	}
}

func (a analyzer) warn(path, code, message string) {
	for _, warning := range a.result.Warnings {
		if warning.Path == path && warning.Code == code && warning.Message == message {
			return
		}
	}
	a.result.Warnings = append(a.result.Warnings, rules.Warning{Path: path, Code: code, Message: message})
}

type findingInput struct {
	ruleID         string
	severity       rules.Severity
	summary        string
	kind           string
	value          string
	expression     string
	decodedSHA256  string
	classification string
	decoder        string
	line           int
	column         int
}

func (a analyzer) addFinding(file File, in findingInput) {
	finding := rules.Finding{
		SchemaVersion: rules.FindingSchemaVersion,
		Severity:      in.severity,
		Confidence:    rules.ConfidenceWeakSignal,
		Source:        sourceName,
		RuleID:        in.ruleID,
		RuleType:      "javascript-obfuscation",
		Summary:       in.summary,
		Path:          file.Path,
		FileHash:      file.SHA256,
		PackageOwner:  file.PackageOwner,
		Location:      &rules.Location{Path: file.Path, Line: in.line, Column: in.column},
		Evidence: []rules.Evidence{{
			Kind:           in.kind,
			Value:          in.value,
			Path:           file.Path,
			FileHash:       file.SHA256,
			Expression:     in.expression,
			DecodedSHA256:  in.decodedSHA256,
			Classification: in.classification,
			Decoder:        in.decoder,
			Line:           in.line,
			Column:         in.column,
		}},
	}
	finding.ID = findingID(finding)
	if _, ok := a.seen[finding.ID]; ok {
		return
	}
	a.seen[finding.ID] = struct{}{}
	a.result.Findings = append(a.result.Findings, finding)
}

type exprValue struct {
	text    string
	expr    string
	derived bool
	line    int
	column  int
}

func constants(tokens []token) map[string]exprValue {
	env := map[string]exprValue{}
	for i := 0; i < len(tokens)-3; i++ {
		if tokens[i].kind != tokenIdent || !isVarKeyword(tokens[i].value) || tokens[i+1].kind != tokenIdent || tokens[i+2].value != "=" {
			continue
		}
		end := i + 3
		for end < len(tokens) && tokens[end].value != ";" {
			if isVarKeyword(tokens[end].value) && end > i+3 {
				break
			}
			end++
		}
		value, ok := evalExpression(tokens[i+3:end], env, 0)
		if !ok {
			continue
		}
		value.line = tokens[i+1].line
		value.column = tokens[i+1].column
		env[tokens[i+1].value] = value
		i = end
	}
	return env
}

func evalExpression(tokens []token, env map[string]exprValue, depth int) (exprValue, bool) {
	tokens = trimParens(trimTokens(tokens))
	if len(tokens) == 0 || depth > 8 {
		return exprValue{}, false
	}
	if parts := splitTopLevel(tokens, "+"); len(parts) > 1 {
		var b strings.Builder
		derived := true
		for _, part := range parts {
			value, ok := evalExpression(part, env, depth+1)
			if !ok {
				return exprValue{}, false
			}
			b.WriteString(value.text)
			derived = derived || value.derived
		}
		return exprValue{text: b.String(), expr: exprText(tokens), derived: derived, line: tokens[0].line, column: tokens[0].column}, true
	}
	if value, ok := evalSimple(tokens, env, depth); ok {
		return value, true
	}
	if value, ok := evalArrayJoin(tokens, env, depth); ok {
		return value, true
	}
	if value, ok := evalDecoder(tokens, env, depth); ok {
		return value, true
	}
	if value, ok := evalMethodChain(tokens, env, depth); ok {
		return value, true
	}
	return exprValue{}, false
}

func evalSimple(tokens []token, env map[string]exprValue, _ int) (exprValue, bool) {
	if len(tokens) != 1 {
		return exprValue{}, false
	}
	switch tokens[0].kind {
	case tokenString:
		return exprValue{text: tokens[0].value, expr: tokens[0].raw, line: tokens[0].line, column: tokens[0].column}, true
	case tokenIdent:
		value, ok := env[tokens[0].value]
		if !ok {
			return exprValue{}, false
		}
		value.derived = true
		value.expr = tokens[0].value
		return value, true
	default:
		return exprValue{}, false
	}
}

func evalArrayJoin(tokens []token, env map[string]exprValue, depth int) (exprValue, bool) {
	if len(tokens) < 5 || tokens[0].value != "[" {
		return exprValue{}, false
	}
	endArray := findMatching(tokens, 0)
	if endArray < 1 || endArray+1 >= len(tokens) {
		return exprValue{}, false
	}
	parts := splitTopLevel(tokens[1:endArray], ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value, ok := evalExpression(part, env, depth+1)
		if !ok {
			return exprValue{}, false
		}
		values = append(values, value.text)
	}
	rest := tokens[endArray+1:]
	reversed := false
	if len(rest) >= 4 && rest[0].value == "." && rest[1].value == "reverse" && rest[2].value == "(" && rest[3].value == ")" {
		reversed = true
		rest = rest[4:]
	}
	if len(rest) < 5 || rest[0].value != "." || rest[1].value != "join" || rest[2].value != "(" {
		return exprValue{}, false
	}
	endJoin := findMatching(rest, 2)
	if endJoin < 0 {
		return exprValue{}, false
	}
	sep := ""
	if endJoin > 3 {
		value, ok := evalExpression(rest[3:endJoin], env, depth+1)
		if !ok {
			return exprValue{}, false
		}
		sep = value.text
	}
	if reversed {
		slices.Reverse(values)
	}
	return exprValue{text: strings.Join(values, sep), expr: exprText(tokens), derived: true, line: tokens[0].line, column: tokens[0].column}, true
}

func evalDecoder(tokens []token, env map[string]exprValue, depth int) (exprValue, bool) {
	if len(tokens) >= 4 && tokens[0].kind == tokenIdent && tokens[1].value == "(" {
		end := findMatching(tokens, 1)
		if end == len(tokens)-1 {
			args := splitTopLevel(tokens[2:end], ",")
			if len(args) > 0 {
				input, ok := evalExpression(args[0], env, depth+1)
				if ok {
					switch tokens[0].value {
					case "atob":
						if decoded, ok := decodeBase64(input.text); ok {
							return exprValue{text: string(decoded), expr: exprText(tokens), derived: true, line: tokens[0].line, column: tokens[0].column}, true
						}
					case "decodeURIComponent", "unescape":
						if decoded, err := url.QueryUnescape(strings.ReplaceAll(input.text, "%20", "+")); err == nil {
							return exprValue{text: decoded, expr: exprText(tokens), derived: true, line: tokens[0].line, column: tokens[0].column}, true
						}
					}
				}
			}
		}
	}
	if len(tokens) >= 6 && tokens[0].value == "String" && tokens[1].value == "." && tokens[2].value == "fromCharCode" && tokens[3].value == "(" {
		end := findMatching(tokens, 3)
		if end == len(tokens)-1 {
			args := splitTopLevel(tokens[4:end], ",")
			var b strings.Builder
			for _, arg := range args {
				if len(arg) != 1 || arg[0].kind != tokenNumber {
					return exprValue{}, false
				}
				n, err := strconv.Atoi(arg[0].value)
				if err != nil || n < 0 || n > utf8.MaxRune {
					return exprValue{}, false
				}
				b.WriteRune(rune(n))
			}
			return exprValue{text: b.String(), expr: exprText(tokens), derived: true, line: tokens[0].line, column: tokens[0].column}, true
		}
	}
	if len(tokens) >= 8 && tokens[0].value == "Buffer" && tokens[1].value == "." && tokens[2].value == "from" && tokens[3].value == "(" {
		end := findMatching(tokens, 3)
		if end < 0 {
			return exprValue{}, false
		}
		args := splitTopLevel(tokens[4:end], ",")
		if len(args) == 0 {
			return exprValue{}, false
		}
		input, ok := evalExpression(args[0], env, depth+1)
		if !ok {
			return exprValue{}, false
		}
		encodingName := "base64"
		if len(args) > 1 {
			if enc, ok := evalExpression(args[1], env, depth+1); ok {
				encodingName = strings.ToLower(enc.text)
			}
		}
		var decoded []byte
		switch encodingName {
		case "base64", "base64url":
			decoded, ok = decodeBase64(input.text)
		case "hex":
			decoded, ok = decodeHex(input.text)
		default:
			return exprValue{}, false
		}
		if !ok {
			return exprValue{}, false
		}
		return exprValue{text: string(decoded), expr: exprText(tokens), derived: true, line: tokens[0].line, column: tokens[0].column}, true
	}
	return exprValue{}, false
}

func evalMethodChain(tokens []token, env map[string]exprValue, depth int) (exprValue, bool) {
	if len(tokens) < 5 {
		return exprValue{}, false
	}
	baseEnd := 1
	if tokens[0].value == "(" {
		baseEnd = findMatching(tokens, 0) + 1
		if baseEnd <= 0 {
			return exprValue{}, false
		}
	}
	value, ok := evalExpression(tokens[:baseEnd], env, depth+1)
	if !ok {
		return exprValue{}, false
	}
	for i := baseEnd; i < len(tokens); {
		if i+3 >= len(tokens) || tokens[i].value != "." || tokens[i+2].value != "(" {
			return exprValue{}, false
		}
		method := tokens[i+1].value
		end := findMatching(tokens, i+2)
		if end < 0 {
			return exprValue{}, false
		}
		args := splitTopLevel(tokens[i+3:end], ",")
		switch method {
		case "replace":
			if len(args) < 2 {
				return exprValue{}, false
			}
			oldValue, ok := evalExpression(args[0], env, depth+1)
			if !ok {
				return exprValue{}, false
			}
			newValue, ok := evalExpression(args[1], env, depth+1)
			if !ok {
				return exprValue{}, false
			}
			value.text = strings.ReplaceAll(value.text, oldValue.text, newValue.text)
		case "split":
			if len(args) != 1 {
				return exprValue{}, false
			}
			sep, ok := evalExpression(args[0], env, depth+1)
			if !ok || sep.text != "" {
				return exprValue{}, false
			}
		case "reverse":
			runes := []rune(value.text)
			slices.Reverse(runes)
			value.text = string(runes)
		case "join", "toString":
		default:
			return exprValue{}, false
		}
		value.derived = true
		value.expr = exprText(tokens)
		i = end + 1
	}
	return value, true
}

type decodedValue struct {
	bytes          []byte
	text           string
	decoder        string
	classification string
}

func decodeSuspiciousString(value, raw string) (decodedValue, bool) {
	candidates := []struct {
		decoder string
		data    []byte
		ok      bool
	}{
		{decoder: "base64", data: mustBytes(decodeBase64(value))},
		{decoder: "hex", data: mustBytes(decodeHex(value))},
		{decoder: "percent", data: mustBytes(decodePercent(value))},
	}
	if strings.Contains(raw, `\u`) || strings.Contains(raw, `\x`) {
		candidates = append(candidates, struct {
			decoder string
			data    []byte
			ok      bool
		}{decoder: "unicode_escape", data: []byte(value), ok: len(value) > 0})
	}
	for _, candidate := range candidates {
		if len(candidate.data) == 0 {
			continue
		}
		if !looksRecovered(candidate.data) {
			continue
		}
		return decodedValue{
			bytes:          candidate.data,
			text:           string(candidate.data),
			decoder:        candidate.decoder,
			classification: classifyPayload(candidate.data),
		}, true
	}
	return decodedValue{}, false
}

func mustBytes(data []byte, ok bool) []byte {
	if !ok {
		return nil
	}
	return data
}

func decodeBase64(value string) ([]byte, bool) {
	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)
	if len(compact) < 12 {
		return nil, false
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		data, err := encoding.DecodeString(compact)
		if err == nil {
			return data, true
		}
	}
	return nil, false
}

func decodeHex(value string) ([]byte, bool) {
	if len(value) < 16 || len(value)%2 != 0 {
		return nil, false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return nil, false
		}
	}
	data, err := hex.DecodeString(value)
	return data, err == nil
}

func decodePercent(value string) ([]byte, bool) {
	if !strings.Contains(value, "%") {
		return nil, false
	}
	decoded, err := url.QueryUnescape(strings.ReplaceAll(value, "%20", "+"))
	if err != nil || decoded == value {
		return nil, false
	}
	return []byte(decoded), true
}

func looksRecovered(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b <= 0x7e) {
			printable++
		}
	}
	if float64(printable)/float64(len(data)) < 0.85 {
		return isBinaryPayload(data)
	}
	text := strings.ToLower(string(data))
	return strings.ContainsAny(text, "{}();=$/") ||
		strings.Contains(text, "http") ||
		strings.Contains(text, "require") ||
		strings.Contains(text, "process") ||
		strings.Contains(text, "curl")
}

func classifyPayload(data []byte) string {
	text := strings.TrimSpace(strings.ToLower(string(data)))
	switch {
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return "pe"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return "elf"
	case len(data) >= 4 && (bytes.Equal(data[:4], []byte{0xfe, 0xed, 0xfa, 0xce}) || bytes.Equal(data[:4], []byte{0xcf, 0xfa, 0xed, 0xfe})):
		return "mach-o"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 0x03, 0x04}):
		return "archive"
	case strings.HasPrefix(text, "{") || strings.HasPrefix(text, "["):
		return "json"
	case strings.HasPrefix(text, "#!") || strings.Contains(text, "/bin/sh") || strings.Contains(text, "curl ") || strings.Contains(text, "powershell"):
		return "shell"
	case strings.Contains(text, "function") || strings.Contains(text, "require(") || strings.Contains(text, "process.") || strings.Contains(text, "console."):
		return "javascript"
	case strings.HasPrefix(text, "http://") || strings.HasPrefix(text, "https://") || strings.Contains(text, "\nhttp"):
		return "url-list"
	case isBinaryPayload(data):
		return "binary"
	default:
		return "unknown"
	}
}

func isBinaryPayload(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

func entropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range value {
		counts[r]++
	}
	var total float64
	size := float64(len([]rune(value)))
	for _, count := range counts {
		p := float64(count) / size
		total -= p * math.Log2(p)
	}
	return total
}

type tokenKind int

const (
	tokenIdent tokenKind = iota
	tokenString
	tokenNumber
	tokenPunct
)

type token struct {
	kind   tokenKind
	value  string
	raw    string
	line   int
	column int
}

func lex(data []byte) []token {
	source := []rune(string(data))
	tokens := []token{}
	line, column := 1, 1
	for i := 0; i < len(source); {
		r := source[i]
		if r == '\n' {
			line++
			column = 1
			i++
			continue
		}
		if unicode.IsSpace(r) {
			column++
			i++
			continue
		}
		if r == '/' && i+1 < len(source) && source[i+1] == '/' {
			for i < len(source) && source[i] != '\n' {
				i++
				column++
			}
			continue
		}
		if r == '/' && i+1 < len(source) && source[i+1] == '*' {
			i += 2
			column += 2
			for i+1 < len(source) && !(source[i] == '*' && source[i+1] == '/') {
				if source[i] == '\n' {
					line++
					column = 1
				} else {
					column++
				}
				i++
			}
			if i+1 < len(source) {
				i += 2
				column += 2
			}
			continue
		}
		startLine, startColumn := line, column
		if isIdentStart(r) {
			start := i
			for i < len(source) && isIdentPart(source[i]) {
				i++
				column++
			}
			tokens = append(tokens, token{kind: tokenIdent, value: string(source[start:i]), raw: string(source[start:i]), line: startLine, column: startColumn})
			continue
		}
		if unicode.IsDigit(r) {
			start := i
			for i < len(source) && (unicode.IsDigit(source[i]) || source[i] == 'x' || source[i] == 'X' || (source[i] >= 'a' && source[i] <= 'f') || (source[i] >= 'A' && source[i] <= 'F')) {
				i++
				column++
			}
			tokens = append(tokens, token{kind: tokenNumber, value: string(source[start:i]), raw: string(source[start:i]), line: startLine, column: startColumn})
			continue
		}
		if r == '\'' || r == '"' || r == '`' {
			value, raw, next, newLine, newColumn := readString(source, i, line, column)
			tokens = append(tokens, token{kind: tokenString, value: value, raw: raw, line: startLine, column: startColumn})
			i, line, column = next, newLine, newColumn
			continue
		}
		tokens = append(tokens, token{kind: tokenPunct, value: string(r), raw: string(r), line: startLine, column: startColumn})
		i++
		column++
	}
	return tokens
}

func readString(source []rune, start int, line int, column int) (string, string, int, int, int) {
	quote := source[start]
	var value strings.Builder
	var raw strings.Builder
	raw.WriteRune(quote)
	i := start + 1
	column++
	for i < len(source) {
		r := source[i]
		raw.WriteRune(r)
		i++
		column++
		if r == '\n' {
			line++
			column = 1
		}
		if r == quote {
			break
		}
		if r != '\\' || i >= len(source) {
			value.WriteRune(r)
			continue
		}
		esc := source[i]
		raw.WriteRune(esc)
		i++
		column++
		switch esc {
		case 'n':
			value.WriteRune('\n')
		case 'r':
			value.WriteRune('\r')
		case 't':
			value.WriteRune('\t')
		case 'x':
			if i+1 <= len(source) {
				if decoded, ok := parseHexRunes(source, i, 2); ok {
					value.WriteRune(decoded)
					raw.WriteString(string(source[i : i+2]))
					i += 2
					column += 2
				}
			}
		case 'u':
			if i+3 < len(source) {
				if decoded, ok := parseHexRunes(source, i, 4); ok {
					value.WriteRune(decoded)
					raw.WriteString(string(source[i : i+4]))
					i += 4
					column += 4
				}
			}
		default:
			value.WriteRune(esc)
		}
	}
	return value.String(), raw.String(), i, line, column
}

func parseHexRunes(source []rune, start int, n int) (rune, bool) {
	if start+n > len(source) {
		return 0, false
	}
	value, err := strconv.ParseInt(string(source[start:start+n]), 16, 32)
	if err != nil {
		return 0, false
	}
	return rune(value), true
}

func isIdentStart(r rune) bool {
	return r == '_' || r == '$' || unicode.IsLetter(r)
}

func isIdentPart(r rune) bool {
	return isIdentStart(r) || unicode.IsDigit(r)
}

func splitTopLevel(tokens []token, sep string) [][]token {
	parts := [][]token{}
	start := 0
	depth := 0
	for i, token := range tokens {
		switch token.value {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		}
		if depth == 0 && token.value == sep {
			parts = append(parts, trimTokens(tokens[start:i]))
			start = i + 1
		}
	}
	parts = append(parts, trimTokens(tokens[start:]))
	return parts
}

func findMatching(tokens []token, open int) int {
	if open < 0 || open >= len(tokens) {
		return -1
	}
	closeValue := map[string]string{"(": ")", "[": "]", "{": "}"}[tokens[open].value]
	if closeValue == "" {
		return -1
	}
	depth := 0
	for i := open; i < len(tokens); i++ {
		if tokens[i].value == tokens[open].value {
			depth++
		}
		if tokens[i].value == closeValue {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func trimTokens(tokens []token) []token {
	for len(tokens) > 0 && tokens[0].value == "," {
		tokens = tokens[1:]
	}
	for len(tokens) > 0 && tokens[len(tokens)-1].value == "," {
		tokens = tokens[:len(tokens)-1]
	}
	return tokens
}

func trimParens(tokens []token) []token {
	for len(tokens) >= 2 && tokens[0].value == "(" && findMatching(tokens, 0) == len(tokens)-1 {
		tokens = tokens[1 : len(tokens)-1]
	}
	return tokens
}

func exprText(tokens []token) string {
	var b strings.Builder
	for _, token := range tokens {
		b.WriteString(token.raw)
	}
	return b.String()
}

func readSourceFile(root, rel string, maxBytes int64) ([]byte, error) {
	if !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("unsafe relative path %q", rel)
	}
	f, err := os.OpenInRoot(root, filepath.FromSlash(rel))
	if err != nil {
		return nil, fmt.Errorf("open javascript target %q: %w", rel, err)
	}
	defer func() {
		_ = f.Close()
	}()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read javascript target %q: %w", rel, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("javascript target %q exceeds %d bytes", rel, maxBytes)
	}
	return data, nil
}

func writeDecodedPayload(ctx context.Context, dir, hash string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(hash) != sha256.Size*2 || filepath.Base(hash) != hash {
		return fmt.Errorf("invalid decoded payload hash %q", hash)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create decoded payload dir: %w", err)
	}
	path := filepath.Join(dir, hash+".bin")
	tmp, err := os.CreateTemp(dir, "."+hash+".tmp-*")
	if err != nil {
		return fmt.Errorf("create decoded payload temp file: %w", err)
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write decoded payload temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod decoded payload temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close decoded payload temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace decoded payload: %w", err)
	}
	removeTemp = false
	return nil
}

func isJavaScriptType(kind string) bool {
	switch kind {
	case "javascript", "javascript_react", "typescript", "typescript_react":
		return true
	default:
		return false
	}
}

func isVarKeyword(value string) bool {
	return value == "const" || value == "let" || value == "var"
}

func isSink(value string) bool {
	switch value {
	case "eval", "Function", "setTimeout", "setInterval", "require", "import":
		return true
	default:
		return false
	}
}

func isGlobalAlias(value string) bool {
	switch value {
	case "globalThis", "global", "window", "self", "process", "module", "exports":
		return true
	default:
		return false
	}
}

func isSensitiveGlobal(value string) bool {
	switch value {
	case "process", "module", "exports", "require", "import", "env", "child_process", "fs", "http", "https", "net", "exec", "spawn":
		return true
	default:
		return false
	}
}

func readLimit(maxFileSize int64) int64 {
	if maxFileSize > 0 {
		return maxFileSize
	}
	return defaultReadLimit
}

func sortResult(result *Result) {
	slices.SortFunc(result.Findings, func(a, b rules.Finding) int {
		return strings.Compare(rules.FindingIdentity(a)+"\x00"+a.ID, rules.FindingIdentity(b)+"\x00"+b.ID)
	})
	slices.SortFunc(result.Warnings, func(a, b rules.Warning) int {
		return strings.Compare(a.Path+"\x00"+a.Code+"\x00"+a.Message, b.Path+"\x00"+b.Code+"\x00"+b.Message)
	})
}

func findingID(finding rules.Finding) string {
	parts := []string{rules.FindingIdentity(finding)}
	for _, evidence := range finding.Evidence {
		parts = append(parts,
			evidence.Kind,
			evidence.Value,
			evidence.Expression,
			evidence.DecodedSHA256,
			evidence.Decoder,
			strconv.Itoa(evidence.Line),
			strconv.Itoa(evidence.Column),
		)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func trimEvidence(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 120 {
		return value[:120]
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
