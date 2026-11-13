package secrets

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Keyword detection follows the approach of the detect-secrets KeywordDetector
// (keyword denylist + assignment shapes), rewritten for RE2 (no lookarounds or
// back-references) and for free text: one general assignment pattern finds
// `key <op> value` shapes, then the key and the value are classified in Go.

const keywordRulePrefix = "keyword:"

// Keyword groups, reported as keyword:<group>.
const (
	groupPassword      = "password"
	groupSecret        = "secret"
	groupAPIKey        = "api_key"
	groupToken         = "token"
	groupCredential    = "credential"
	groupAuthorization = "authorization"
	groupBearer        = "bearer"
	groupURLCredential = "url_credential"
)

func keywordRuleNames() []string {
	groups := []string{groupPassword, groupSecret, groupAPIKey, groupToken, groupCredential, groupAuthorization, groupBearer, groupURLCredential}
	names := make([]string, len(groups))
	for i, group := range groups {
		names[i] = keywordRulePrefix + group
	}
	return names
}

// hspace is horizontal white space, including no-break and narrow no-break
// spaces (French typography puts one before ':').
const hspace = `[\t\p{Zs}]`

// assignmentPattern matches `key <op> value` on one line. Operators: `:=`,
// `=>`, `=`, `==`, `===`, `!=`, `!==`, `:`, `>` (XML elements, as in the
// gitleaks generic rule) and the full-width ':' and '=', or
// the prose connectors "is", "est", "was". Values are a quoted string, where
// a backslash escapes the next character, an escaped-JSON string (`\"x\"`,
// as in JSON embedded in a JSON string, where an inner quote is `\\\"` and
// an inner backslash `\\\\`), or an unquoted run up to white space or a
// delimiter. Keys may be closed by quotes, escaped quotes or ']'.
var assignmentPattern = regexp.MustCompile(
	`(?P<key>(?i:mot[ _-]?de[ _-]?passe)|[\pL\pN_.\-]{1,64})` +
		"(?:\\\\?[\"'`\\]]){0,2}" +
		`(?:` + hspace + `*(?P<op>:=|=>|={1,3}|!==?|:|>|\x{FF1A}|\x{FF1D})` + hspace + `*` +
		`|` + hspace + `+(?i:is|est|was)` + hspace + `+)` +
		`(?P<value>\\"(?:[^"\\\n]|\\\\\\"|\\\\\\\\|\\\\[^"\\\n]|\\[^"\\\n])*\\"|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|` + "`[^`\\n]*`" +
		`|[^\s\p{Zs}"'` + "`" + `,;&<>(){}\[\]]+)`)

// urlCredentialPattern matches the password of URL user information
// (scheme://user:password@host).
var urlCredentialPattern = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]{1,15}://[^\s/?#@:"'<>]*:([^\s/?#"'<>]+)@`)

// bearerPattern matches an RFC 6750 bearer credential outside an assignment.
var bearerPattern = regexp.MustCompile(`(?i)\bbearer` + hspace + `+([A-Za-z0-9\-._~+/]+=*)`)

const minBearerLength = 16

var (
	assignKey   = assignmentPattern.SubexpIndex("key")
	assignOp    = assignmentPattern.SubexpIndex("op")
	assignValue = assignmentPattern.SubexpIndex("value")
)

// assignment is one `key <op> value` occurrence, in byte offsets. The value
// span excludes quotes.
type assignment struct {
	valueStart int
	valueEnd   int
	quoted     bool
	comparison bool   // ==, ===, != or !==: an unquoted operand is an identifier
	group      string // secret keyword group of the key, "" when none
	idLike     bool   // the key names an identifier (user_id, keyId...)
}

func findAssignments(view *textView) []assignment {
	var found []assignment
	collectAssignments(view.text, 0, len(view.text), &found)
	return found
}

// collectAssignments appends the assignments of text[from:to]. A match whose
// key is not a secret key may hide one in its value ("Here is password=x",
// `note: "password=x"`): quoted values are searched again (each quote kind
// ends a nesting level, so the depth is bounded) and unquoted values are
// tokenized by nestedAssignment. When such a value ends with a secret key
// whose own value lies past the match ("Here is password = x",
// `Here is password="x"`), the search resumes at that key; the key is at
// most maxKeyRunes long, so the whole scan stays linear.
func collectAssignments(text string, from, to int, found *[]assignment) {
	for from < to {
		m := assignmentPattern.FindStringSubmatchIndex(text[from:to])
		if m == nil {
			return
		}
		next := from + m[1]
		key := text[from+m[2*assignKey] : from+m[2*assignKey+1]]
		valueStart, valueEnd := from+m[2*assignValue], from+m[2*assignValue+1]
		quoted := false
		if strings.HasPrefix(text[valueStart:valueEnd], `\"`) && valueEnd-valueStart >= 4 {
			quoted = true
			valueStart += 2
			valueEnd -= 2
		} else if c := text[valueStart]; c == '"' || c == '\'' || c == '`' {
			quoted = true
			valueStart++
			valueEnd--
		}
		group, idLike := classifyKey(key)
		op := ""
		if m[2*assignOp] >= 0 {
			op = text[from+m[2*assignOp] : from+m[2*assignOp+1]]
		}
		a := assignment{
			valueStart: valueStart,
			valueEnd:   valueEnd,
			quoted:     quoted,
			comparison: isComparison(op),
			group:      group,
			idLike:     idLike,
		}
		if group == groupAuthorization {
			a = authorizationCredential(text, a)
		}
		*found = append(*found, a)
		switch {
		case group != "" || valueEnd <= valueStart:
		case quoted:
			collectAssignments(text, valueStart, valueEnd, found)
		default:
			if nested, ok := nestedAssignment(text, valueStart, valueEnd); ok {
				*found = append(*found, nested)
			} else if keyStart, ok := trailingSecretKey(text, valueStart, valueEnd); ok {
				next = keyStart
			}
		}
		from = next
	}
}

// trailingSecretKey returns the start of the secret key that ends the
// unquoted value text[start:end], possibly followed by operators
// ("password" or "password="), so its own value can be matched. The key
// starts inside the value, after the match start, so resuming progresses.
func trailingSecretKey(text string, start, end int) (int, bool) {
	for end > start {
		r, size := utf8.DecodeLastRuneInString(text[start:end])
		if !isOperatorRune(r) {
			break
		}
		end -= size
	}
	keyStart := end
	for n := 0; n < maxKeyRunes && keyStart > start; n++ {
		r, size := utf8.DecodeLastRuneInString(text[start:keyStart])
		if !isKeyRune(r) {
			break
		}
		keyStart -= size
	}
	if keyStart == end {
		return 0, false
	}
	group, _ := classifyKey(text[keyStart:end])
	return keyStart, group != ""
}

func isComparison(op string) bool {
	return op == "==" || op == "===" || op == "!=" || op == "!=="
}

func isOperatorRune(r rune) bool {
	return r == ':' || r == '=' || r == '!' || r == '\uFF1A' || r == '\uFF1D'
}

func isKeyRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || r == '.' || r == '-'
}

// maxKeyRunes bounds a key, as the {1,64} key repetition of
// assignmentPattern does.
const maxKeyRunes = 64

// nestedAssignment finds the first secret key assignment inside the unquoted
// value text[start:end] (which has no white space), such as `password=x` in
// `note:password=x`. Keys are the key runes right before an operator run;
// the value runs to end.
func nestedAssignment(text string, start, end int) (assignment, bool) {
	for pos := start; pos < end; {
		r, size := utf8.DecodeRuneInString(text[pos:end])
		if !isOperatorRune(r) {
			pos += size
			continue
		}
		opStart := pos
		for pos < end {
			r, size := utf8.DecodeRuneInString(text[pos:end])
			if !isOperatorRune(r) {
				break
			}
			pos += size
		}
		keyStart := opStart
		for n := 0; n < maxKeyRunes && keyStart > start; n++ {
			r, size := utf8.DecodeLastRuneInString(text[start:keyStart])
			if !isKeyRune(r) {
				break
			}
			keyStart -= size
		}
		if keyStart == opStart || pos == end {
			continue
		}
		if group, idLike := classifyKey(text[keyStart:opStart]); group != "" {
			a := assignment{valueStart: pos, valueEnd: end, comparison: isComparison(text[opStart:pos]), group: group, idLike: idLike}
			if group == groupAuthorization {
				a = authorizationCredential(text, a)
			}
			return a, true
		}
	}
	return assignment{}, false
}

// authorizationSchemes are HTTP authentication schemes that precede the
// credential in an Authorization value.
var authorizationSchemes = map[string]bool{"bearer": true, "basic": true, "token": true, "digest": true, "negotiate": true, "apikey": true}

// authorizationCredential moves the value of an Authorization assignment past
// its scheme, so `Authorization: Bearer <credential>` reports the credential.
func authorizationCredential(text string, a assignment) assignment {
	value := text[a.valueStart:a.valueEnd]
	if a.quoted {
		scheme, rest, ok := strings.Cut(value, " ")
		if ok && authorizationSchemes[strings.ToLower(scheme)] {
			trimmed := strings.TrimLeft(rest, " ")
			a.valueStart = a.valueEnd - len(trimmed)
		}
		return a
	}
	if !authorizationSchemes[strings.ToLower(value)] {
		return a
	}
	pos := a.valueEnd
	for pos < len(text) {
		r, size := utf8.DecodeRuneInString(text[pos:])
		if r != '\t' && !unicode.Is(unicode.Zs, r) {
			break
		}
		pos += size
	}
	end := pos
	for end < len(text) {
		r, size := utf8.DecodeRuneInString(text[end:])
		if unicode.IsSpace(r) || strings.ContainsRune("\"'`,;", r) {
			break
		}
		end += size
	}
	if end > pos {
		a.valueStart, a.valueEnd = pos, end
	} else {
		a.valueStart = a.valueEnd // scheme without credential: nothing to report
	}
	return a
}

func scanKeywords(view *textView, assignments []assignment) []rawFinding {
	text := view.text
	var findings []rawFinding
	for _, a := range assignments {
		if a.group == "" || a.valueEnd <= a.valueStart {
			continue
		}
		start, end := a.valueStart, a.valueEnd
		if !a.quoted {
			if a.comparison {
				continue // user.password != confirmPassword compares identifiers
			}
			end = trimSentenceDot(text, start, end)
		}
		if acceptKeywordValue(text, start, end, a.quoted, a.group) {
			findings = append(findings, rawFinding{source: SourceKeyword, rule: keywordRulePrefix + a.group, kind: TypeSecret, start: start, end: end})
		}
	}
	for _, m := range urlCredentialPattern.FindAllStringSubmatchIndex(text, -1) {
		start, end := m[2], m[3]
		if acceptKeywordValue(text, start, end, true, groupPassword) {
			findings = append(findings, rawFinding{source: SourceKeyword, rule: keywordRulePrefix + groupURLCredential, kind: TypeSecret, start: start, end: end})
		}
	}
	for _, m := range bearerPattern.FindAllStringSubmatchIndex(text, -1) {
		start, end := m[2], m[3]
		if end-start >= minBearerLength && acceptKeywordValue(text, start, end, false, groupBearer) {
			findings = append(findings, rawFinding{source: SourceKeyword, rule: keywordRulePrefix + groupBearer, kind: TypeSecret, start: start, end: end})
		}
	}
	return findings
}

// trimSentenceDot drops one final '.' that ends a sentence ("... is s3cr3t.").
func trimSentenceDot(text string, start, end int) int {
	if end-start > 1 && text[end-1] == '.' && (end == len(text) || text[end] == ' ' || text[end] == '\n' || text[end] == '\t' || text[end] == '\r') {
		return end - 1
	}
	return end
}

// Value limits, in characters.
const (
	minQuotedValueLength   = 4
	minUnquotedValueLength = 6
)

var (
	// valueStopwords are values that describe a field instead of filling
	// it (schemas, booleans, empty markers). Compared case-insensitively.
	valueStopwords = setOf("required", "optional", "string", "str", "text", "varchar", "char", "int", "integer",
		"number", "bool", "boolean", "null", "none", "nil", "undefined", "true", "false", "empty", "blank",
		"yes", "no", "on", "off", "n/a", "tbd", "todo", "fixme", "hidden", "masked", "redacted", "removed",
		"secret", "secrets", "password", "passwd", "token", "apikey", "api_key", "credential", "credentials",
		"value", "example", "sample", "dummy", "placeholder", "pass", "pwd")
	// placeholderMarkers flag letter-only values such as YOUR_API_KEY_HERE.
	placeholderMarkers = []string{"your", "here", "example", "placeholder", "insert", "replace", "redacted", "xxx", "dummy", "sample", "fake"}
	upperSnakeIdent    = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	// dottedReference matches attribute paths such as config.password or
	// process.env.API_KEY (digits only at the end of a segment), not dotted
	// credentials such as JWTs.
	dottedReference = regexp.MustCompile(`^[A-Za-z_]+[0-9]*(?:\.[A-Za-z_]+[0-9]*)+$`)
	// dollarReference is the gitleaks global allowlist shape of a shell
	// variable ($DB_PASS, $db_pass): "$ecret123" is a value.
	dollarReference = regexp.MustCompile(`^\$(?:[A-Z_]+|[a-z_]+)$`)
	// templateBody is the inside of a template marker: an identifier or a
	// short phrase, not a value with digits mixed with symbols.
	templateBody     = regexp.MustCompile(`^[\pL_ .\-]*$`)
	pathLike         = regexp.MustCompile(`^(?:~|\.{1,2})?/[\w.\-/]*$`)
	urlLike          = regexp.MustCompile(`^(?i)[a-z][a-z0-9+.\-]*://`)
	letterSeparators = regexp.MustCompile(`^[A-Za-z_\-]+$`)
)

// acceptKeywordValue decides whether an assignment value is reported. The
// rules are deterministic and described in the package README.
func acceptKeywordValue(text string, start, end int, quoted bool, group string) bool {
	value := text[start:end]
	length := utf8.RuneCountInString(value)
	if quoted && length < minQuotedValueLength || !quoted && length < minUnquotedValueLength {
		return false
	}
	if isPlaceholder(value) {
		return false
	}
	letters, digits, symbols, innerUpper := profile(value)
	if letters == 0 && digits == 0 {
		return false
	}
	if letters == 0 && symbols == 0 && group != groupPassword {
		// Counters such as `token: 4096` or `max_tokens=128000`.
		return false
	}
	if quoted {
		return true
	}
	// Unquoted values: references and prose are not secrets.
	if end < len(text) && (text[end] == '(' || text[end] == '[') {
		return false // indirect reference: get_secret(), env['KEY']
	}
	if upperSnakeIdent.MatchString(value) || dottedReference.MatchString(value) ||
		pathLike.MatchString(value) || urlLike.MatchString(value) {
		return false
	}
	// A plain word (letters, hyphens, underscores, dots) is prose or a
	// reference; credentials carry a digit, a symbol or inner capitals.
	return digits > 0 || symbols > 0 || innerUpper
}

func isPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	if valueStopwords[lower] {
		return true
	}
	if isRepeatedRune(value) {
		return true // ******, xxxxxx, ......
	}
	if isTemplated(value) || dollarReference.MatchString(value) {
		return true
	}
	if letterSeparators.MatchString(value) {
		for _, marker := range placeholderMarkers {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	return false
}

// isTemplated extends detect-secrets is_templated_secret: {x}, <x>, ${x},
// {{ x }}, %x%, %(x)s and [x] (e.g. [REDACTED]), where x is made of letters,
// '_', '.', '-' and spaces: "<Tr0ub4dor&3x>" is a value, not a template.
func isTemplated(value string) bool {
	if len(value) < 2 {
		return true
	}
	first, last := value[0], value[len(value)-1]
	body := ""
	switch {
	case strings.HasPrefix(value, "${") && last == '}':
		body = value[2 : len(value)-1]
	case strings.HasPrefix(value, "%(") && strings.HasSuffix(value, ")s") && len(value) >= 4:
		body = value[2 : len(value)-2]
	case first == '{' && last == '}', first == '<' && last == '>', first == '[' && last == ']',
		first == '%' && last == '%':
		body = strings.Trim(value[1:len(value)-1], "{}")
	default:
		return false
	}
	return templateBody.MatchString(body)
}

func isRepeatedRune(value string) bool {
	first, _ := utf8.DecodeRuneInString(value)
	for _, r := range value {
		if r != first {
			return false
		}
	}
	return true
}

// profile counts character classes. innerUpper reports an upper-case letter
// after the first character (mixed case such as "s3Cr3t" or "aBc").
func profile(value string) (letters, digits, symbols int, innerUpper bool) {
	for i, r := range value {
		switch {
		case unicode.IsLetter(r):
			letters++
			if i > 0 && unicode.IsUpper(r) {
				innerUpper = true
			}
		case unicode.IsDigit(r):
			digits++
		case r == '-' || r == '_' || r == '.':
			// word separators do not make a value look like a credential
		default:
			symbols++
		}
	}
	return letters, digits, symbols, innerUpper
}

// Key classification -------------------------------------------------------

var (
	keyQualifiers = setOf("api", "auth", "service", "account", "db", "database", "priv", "private", "client",
		"access", "secret", "encryption", "signing", "master", "shared", "app", "consumer", "webhook",
		"license", "subscription", "ssh", "gpg", "pgp", "deploy", "admin", "root", "session", "jwt", "hmac",
		"aes", "crypto", "cipher", "x")
	// keyDescriptors after the keyword mean the key describes the secret
	// (password_length, token_url, secret_name, api_key_id) instead of
	// holding it.
	keyDescriptors = setOf("id", "ids", "uuid", "guid", "name", "names", "url", "uri", "urls", "endpoint", "path",
		"paths", "file", "files", "filename", "dir", "location", "length", "len", "size", "type", "kind",
		"format", "count", "max", "min", "limit", "expiry", "expires", "expiration", "ttl", "timeout", "field",
		"fields", "header", "param", "params", "parameter", "policy", "rotation", "version", "label", "hint",
		"prompt", "placeholder", "required", "enabled", "provider", "manager", "store", "vault", "ref",
		"reference", "env", "var", "variable", "regex", "pattern", "mode", "algorithm", "alg", "scheme",
		"prefix", "suffix", "template", "schema", "validator", "validation", "error", "errors", "message",
		"msg", "rules", "requirements", "strength", "usage", "arn")
	// keyNegatingPrefixes before the keyword mean a non-secret value:
	// public keys, CSRF tokens, token counters, pagination tokens.
	keyNegatingPrefixes = setOf("public", "pub", "csrf", "xsrf", "max", "min", "num", "total", "next", "page", "continuation")
	idKeys              = setOf("id", "myid", "userid")
	idSuffixes          = setOf("id", "ids", "uuid", "guid")
	passwordSuffixes    = []string{"password", "passwd", "passphrase", "pwd", "contrasena", "contraseña"}
	passwordQualifiers  = setOf("db", "database", "key")
)

// classifyKey returns the keyword group of a key ("" when it does not name a
// secret) and whether it names an identifier.
//
// Keywords are matched on the words between separators, lower-cased, so the
// letter case cannot hide them (PassWord, dbPassword and DB_PASSWORD all
// contain "password"), and then on camelCase sub-words, so a keyword
// followed by a qualifier is found too (passwordProd, apiKeyValue). The
// sub-words around the keyword recognise descriptors, negating prefixes and
// identifier suffixes (apiKeyId, csrfToken, passwordHint).
func classifyKey(key string) (string, bool) {
	words := splitKey(key)
	if len(words) == 0 {
		return "", false
	}
	last := words[len(words)-1].camel
	idLike := idKeys[strings.ToLower(key)] || (len(last) > 0 && idSuffixes[last[len(last)-1]])
	lowers := make([]string, len(words))
	for i, word := range words {
		lowers[i] = word.lower
	}
	for i, word := range words {
		// before and after are the camel sub-words around the keyword.
		var before, after []string
		for _, w := range words[:i] {
			before = append(before, w.camel...)
		}
		for _, w := range words[i+1:] {
			after = append(after, w.camel...)
		}
		if group, prefix := secretGroupAt(lowers, i); group != "" {
			// The keyword ends the word: every other camel sub-word of the
			// word precedes it (getCsrfToken, myNextPageToken).
			return keyVerdict(group, prefix, append(before, word.camel...), after, idLike)
		}
		if len(word.camel) < 2 {
			continue
		}
		for j := range word.camel {
			if group, prefix := secretGroupAt(word.camel, j); group != "" {
				subBefore := append(append([]string(nil), before...), word.camel[:j]...)
				subAfter := append(append([]string(nil), word.camel[j+1:]...), after...)
				return keyVerdict(group, prefix, subBefore, subAfter, idLike)
			}
		}
	}
	return "", idLike
}

// keyVerdict applies negating prefixes and descriptors around a keyword.
func keyVerdict(group, prefix string, before, after []string, idLike bool) (string, bool) {
	if prefix != "" && isNegatingPrefix(prefix) {
		return "", idLike
	}
	for _, sub := range before {
		if keyNegatingPrefixes[sub] {
			return "", idLike
		}
	}
	for _, sub := range after {
		if keyDescriptors[sub] {
			return "", idLike
		}
	}
	return group, false
}

// isNegatingPrefix reports whether prefix, the part of a word before its
// keyword, is made only of negating prefixes ("csrf", "nextpage",
// "maxtotal"). A word that merely ends with one is not: "admin" ends with
// "min" but adminpassword holds a password.
func isNegatingPrefix(prefix string) bool {
	if prefix == "" {
		return true
	}
	for negating := range keyNegatingPrefixes {
		if strings.HasPrefix(prefix, negating) && isNegatingPrefix(prefix[len(negating):]) {
			return true
		}
	}
	return false
}

// secretGroupAt returns the keyword group of words[i] and the part of the
// word before the keyword (e.g. "db" for "dbpassword").
func secretGroupAt(words []string, i int) (string, string) {
	word := words[i]
	if word == "mdp" || word == "motdepasse" || word == "dbpass" || word == "databasepass" || word == "keypass" {
		return groupPassword, ""
	}
	for _, suffix := range passwordSuffixes {
		if strings.HasSuffix(word, suffix) {
			return groupPassword, strings.TrimSuffix(word, suffix)
		}
	}
	switch {
	case word == "pass" && i > 0 && passwordQualifiers[words[i-1]]:
		return groupPassword, ""
	case word == "mot" && i+2 < len(words) && words[i+1] == "de" && words[i+2] == "passe":
		return groupPassword, ""
	case word == "secrets":
		return groupSecret, ""
	case strings.HasSuffix(word, "secret"):
		return groupSecret, strings.TrimSuffix(word, "secret")
	case word == "key" || word == "keys":
		if i > 0 && keyQualifiers[words[i-1]] {
			return groupAPIKey, ""
		}
	case strings.HasSuffix(word, "key") && keyQualifiers[strings.TrimSuffix(word, "key")]:
		return groupAPIKey, ""
	case strings.HasSuffix(word, "token"):
		return groupToken, strings.TrimSuffix(word, "token")
	case word == "credential" || word == "credentials" || word == "creds":
		return groupCredential, ""
	case word == "authorization":
		return groupAuthorization, ""
	}
	return "", ""
}

// keyWord is one separator-delimited word of a key: lower-cased without
// trailing digits, and split into lower-cased camelCase sub-words.
type keyWord struct {
	lower string
	camel []string
}

func splitKey(key string) []keyWord {
	var words []keyWord
	for _, part := range strings.FieldsFunc(key, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		lower := strings.TrimRight(strings.ToLower(part), "0123456789")
		if lower == "" {
			continue
		}
		words = append(words, keyWord{lower: lower, camel: keyTokens(part)})
	}
	return words
}

// keyTokens splits a key into lower-case words on separators and camelCase
// boundaries, without trailing digits: "DB_PASSWORD2" -> [db password],
// "clientSecret" -> [client secret], "APIKey" -> [api key].
func keyTokens(key string) []string {
	var tokens []string
	runes := []rune(key)
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		word := strings.TrimRight(strings.ToLower(string(runes[start:end])), "0123456789")
		if word != "" {
			tokens = append(tokens, word)
		}
		start = -1
	}
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush(i)
			continue
		}
		if start >= 0 && i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush(i)
			}
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(runes))
	return tokens
}
