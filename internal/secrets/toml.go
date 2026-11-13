package secrets

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file implements the strict TOML subset used by the vendored gitleaks
// rules file. No TOML library is a dependency of this module, and the rules
// file only uses a small, stable part of the language. Anything outside that
// subset is a load error, so an upstream refresh that adopts a new construct
// fails the unit tests instead of being misread.
//
// Supported: comments; the table headers listed in tomlTables; bare keys;
// basic strings ("..." with \" \\ \b \f \n \r \t \uXXXX \UXXXXXXXX escapes);
// literal strings ('...' and single-line '''...'''); integers; decimal floats;
// booleans; arrays of strings spanning several lines with trailing commas and
// comments. Duplicate keys within one table are rejected.

type tomlTableKind int

const (
	tomlRoot tomlTableKind = iota
	tomlGlobalAllowlist
	tomlGlobalAllowlists
	tomlRule
	tomlRuleAllowlist
)

// tomlTables maps the accepted headers onto their kind. Only array-of-tables
// headers ([[...]]) may repeat.
var tomlTables = map[string]tomlTableKind{
	"[allowlist]":          tomlGlobalAllowlist,
	"[[allowlists]]":       tomlGlobalAllowlists,
	"[[rules]]":            tomlRule,
	"[[rules.allowlists]]": tomlRuleAllowlist,
}

type tomlValueKind int

const (
	tomlString tomlValueKind = iota
	tomlInteger
	tomlFloat
	tomlBool
	tomlStringArray
)

type tomlValue struct {
	kind    tomlValueKind
	str     string
	num     float64
	integer int64
	boolean bool
	strs    []string
	line    int
}

// tomlTable is one table instance in file order.
type tomlTable struct {
	kind   tomlTableKind
	line   int
	values map[string]tomlValue
}

type tomlParser struct {
	src  string
	pos  int
	line int
}

func parseTOMLSubset(src string) ([]tomlTable, error) {
	if !utf8.ValidString(src) {
		return nil, fmt.Errorf("rules file is not valid UTF-8")
	}
	p := &tomlParser{src: src, line: 1}
	tables := []tomlTable{{kind: tomlRoot, line: 1, values: map[string]tomlValue{}}}
	seenSingle := map[tomlTableKind]bool{}
	for {
		p.skipBlankAndComments()
		if p.eof() {
			return tables, nil
		}
		if p.peek() == '[' {
			header, err := p.readHeader()
			if err != nil {
				return nil, err
			}
			kind, ok := tomlTables[header]
			if !ok {
				return nil, p.errorf("unsupported table %s", header)
			}
			if !strings.HasPrefix(header, "[[") {
				if seenSingle[kind] {
					return nil, p.errorf("duplicate table %s", header)
				}
				seenSingle[kind] = true
			}
			if kind == tomlRuleAllowlist && !hasRule(tables) {
				return nil, p.errorf("%s before any [[rules]]", header)
			}
			tables = append(tables, tomlTable{kind: kind, line: p.line, values: map[string]tomlValue{}})
			if err := p.endOfLine(); err != nil {
				return nil, err
			}
			continue
		}
		key, value, err := p.readKeyValue()
		if err != nil {
			return nil, err
		}
		current := tables[len(tables)-1].values
		if _, dup := current[key]; dup {
			return nil, p.errorf("duplicate key %q", key)
		}
		current[key] = value
		if err := p.endOfLine(); err != nil {
			return nil, err
		}
	}
}

func hasRule(tables []tomlTable) bool {
	for _, table := range tables {
		if table.kind == tomlRule {
			return true
		}
	}
	return false
}

func (p *tomlParser) eof() bool { return p.pos >= len(p.src) }

func (p *tomlParser) peek() byte { return p.src[p.pos] }

func (p *tomlParser) errorf(format string, args ...any) error {
	return fmt.Errorf("rules file line %d: %s", p.line, fmt.Sprintf(format, args...))
}

func (p *tomlParser) skipSpaces() {
	for !p.eof() && (p.peek() == ' ' || p.peek() == '\t') {
		p.pos++
	}
}

func (p *tomlParser) skipComment() {
	if !p.eof() && p.peek() == '#' {
		for !p.eof() && p.peek() != '\n' {
			p.pos++
		}
	}
}

func (p *tomlParser) newline() bool {
	if p.eof() {
		return false
	}
	if p.peek() == '\n' {
		p.pos++
		p.line++
		return true
	}
	if strings.HasPrefix(p.src[p.pos:], "\r\n") {
		p.pos += 2
		p.line++
		return true
	}
	return false
}

func (p *tomlParser) skipBlankAndComments() {
	for {
		p.skipSpaces()
		p.skipComment()
		if !p.newline() {
			return
		}
	}
}

// endOfLine accepts trailing spaces and a comment before the newline or EOF.
func (p *tomlParser) endOfLine() error {
	p.skipSpaces()
	p.skipComment()
	if p.eof() || p.newline() {
		return nil
	}
	return p.errorf("unexpected content after value")
}

func (p *tomlParser) readHeader() (string, error) {
	end := strings.IndexByte(p.src[p.pos:], '\n')
	if end < 0 {
		end = len(p.src) - p.pos
	}
	lineText := p.src[p.pos : p.pos+end]
	closing := strings.LastIndexByte(lineText, ']')
	if closing < 0 {
		return "", p.errorf("unterminated table header")
	}
	header := lineText[:closing+1]
	p.pos += closing + 1
	return header, nil
}

func isBareKeyByte(c byte) bool {
	return c == '_' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func (p *tomlParser) readKeyValue() (string, tomlValue, error) {
	start := p.pos
	for !p.eof() && isBareKeyByte(p.peek()) {
		p.pos++
	}
	if p.pos == start {
		return "", tomlValue{}, p.errorf("expected a bare key")
	}
	key := p.src[start:p.pos]
	p.skipSpaces()
	if p.eof() || p.peek() != '=' {
		return "", tomlValue{}, p.errorf("expected '=' after key %q", key)
	}
	p.pos++
	p.skipSpaces()
	value, err := p.readValue(true)
	if err != nil {
		return "", tomlValue{}, err
	}
	return key, value, nil
}

func (p *tomlParser) readValue(allowArray bool) (tomlValue, error) {
	if p.eof() {
		return tomlValue{}, p.errorf("missing value")
	}
	line := p.line
	switch c := p.peek(); {
	case c == '"':
		s, err := p.readBasicString()
		return tomlValue{kind: tomlString, str: s, line: line}, err
	case c == '\'':
		s, err := p.readLiteralString()
		return tomlValue{kind: tomlString, str: s, line: line}, err
	case c == '[':
		if !allowArray {
			return tomlValue{}, p.errorf("nested arrays are not supported")
		}
		strs, err := p.readStringArray()
		return tomlValue{kind: tomlStringArray, strs: strs, line: line}, err
	default:
		return p.readScalar()
	}
}

func (p *tomlParser) readBasicString() (string, error) {
	if strings.HasPrefix(p.src[p.pos:], `"""`) {
		return "", p.errorf("multi-line basic strings are not supported")
	}
	p.pos++ // opening quote
	var b strings.Builder
	for {
		if p.eof() || p.peek() == '\n' {
			return "", p.errorf("unterminated basic string")
		}
		c := p.peek()
		switch c {
		case '"':
			p.pos++
			return b.String(), nil
		case '\\':
			p.pos++
			if p.eof() {
				return "", p.errorf("unterminated escape sequence")
			}
			esc := p.peek()
			p.pos++
			switch esc {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u', 'U':
				size := 4
				if esc == 'U' {
					size = 8
				}
				if p.pos+size > len(p.src) {
					return "", p.errorf("truncated unicode escape")
				}
				code, err := strconv.ParseUint(p.src[p.pos:p.pos+size], 16, 32)
				if err != nil || !utf8.ValidRune(rune(code)) {
					return "", p.errorf("invalid unicode escape")
				}
				p.pos += size
				b.WriteRune(rune(code))
			default:
				return "", p.errorf("unsupported escape sequence \\%c", esc)
			}
		default:
			if c < 0x20 && c != '\t' {
				return "", p.errorf("control character in basic string")
			}
			b.WriteByte(c)
			p.pos++
		}
	}
}

func (p *tomlParser) readLiteralString() (string, error) {
	delimiter := "'"
	if strings.HasPrefix(p.src[p.pos:], "'''") {
		delimiter = "'''"
	}
	p.pos += len(delimiter)
	rest := p.src[p.pos:]
	end := strings.Index(rest, delimiter)
	newline := strings.IndexByte(rest, '\n')
	if end < 0 || (newline >= 0 && newline < end) {
		return "", p.errorf("unterminated or multi-line literal string")
	}
	value := rest[:end]
	p.pos += end + len(delimiter)
	if delimiter == "'''" && !p.eof() && p.peek() == '\'' {
		// '''x'''' is ambiguous in this subset (TOML allows up to two
		// quotes before the closing delimiter); refuse it.
		return "", p.errorf("ambiguous literal string ending")
	}
	return value, nil
}

func (p *tomlParser) readStringArray() ([]string, error) {
	p.pos++ // [
	values := []string{}
	for {
		p.skipBlankAndComments()
		if p.eof() {
			return nil, p.errorf("unterminated array")
		}
		if p.peek() == ']' {
			p.pos++
			return values, nil
		}
		value, err := p.readValue(false)
		if err != nil {
			return nil, err
		}
		if value.kind != tomlString {
			return nil, p.errorf("only arrays of strings are supported")
		}
		values = append(values, value.str)
		p.skipBlankAndComments()
		if p.eof() {
			return nil, p.errorf("unterminated array")
		}
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return values, nil
		default:
			return nil, p.errorf("expected ',' or ']' in array")
		}
	}
}

func (p *tomlParser) readScalar() (tomlValue, error) {
	start := p.pos
	for !p.eof() {
		c := p.peek()
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '#' || c == ',' || c == ']' {
			break
		}
		p.pos++
	}
	raw := p.src[start:p.pos]
	line := p.line
	switch raw {
	case "true":
		return tomlValue{kind: tomlBool, boolean: true, line: line}, nil
	case "false":
		return tomlValue{kind: tomlBool, boolean: false, line: line}, nil
	}
	if integer, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return tomlValue{kind: tomlInteger, integer: integer, num: float64(integer), line: line}, nil
	}
	// Floats are restricted to plain decimals such as 3.5: TOML underscores,
	// exponents, inf and nan are outside the subset.
	if !isPlainDecimal(raw) {
		return tomlValue{}, p.errorf("unsupported value %q", raw)
	}
	number, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return tomlValue{}, p.errorf("unsupported value %q", raw)
	}
	return tomlValue{kind: tomlFloat, num: number, line: line}, nil
}

// isPlainDecimal accepts [+-]?digits.digits.
func isPlainDecimal(raw string) bool {
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "+"), "-")
	intPart, fracPart, ok := strings.Cut(raw, ".")
	return ok && allDigits(intPart) && allDigits(fracPart)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
