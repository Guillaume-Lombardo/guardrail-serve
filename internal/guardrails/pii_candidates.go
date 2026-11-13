package guardrails

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/g1lom/guardrail-serve/internal/validators"
)

var versionPrefix = regexp.MustCompile(`(?i)(?:\b(?:version|release|ver|v)[ :=-]*|\bv)$`)

var frenchIdentifierPrefix = regexp.MustCompile(`(?i)(?:\bNIR|\bSIREN|\bSIRET|numéro de sécurité sociale|sécurité sociale)\s*[:=]?\s*$`)

func identifierBoundary(text string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(text[:start])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return false
		}
	}
	if end < len(text) {
		r, _ := utf8.DecodeRuneInString(text[end:])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return false
		}
	}
	return true
}

// piiCandidateEnd confirms normalized candidates before mapping to original text.
func piiCandidateEnd(rule compiledRule, text string, start, end int) int {
	if (rule.validator != "" || rule.kind == "PHONE_NUMBER" || rule.kind == "IP_ADDRESS") && !identifierBoundary(text, start, end) {
		return start
	}
	if rule.validator == validators.KindPaymentCard && frenchIdentifierPrefix.MatchString(text[:start]) {
		return start
	}
	if rule.validator == validators.KindIBAN {
		// A grouped IBAN regex can consume following prose. Only shorten at a
		// separator; never accept a valid prefix of a longer identifier.
		for candidateEnd := end; candidateEnd > start; candidateEnd-- {
			if candidateEnd != end && text[candidateEnd] != ' ' && text[candidateEnd] != '-' {
				continue
			}
			candidate := text[start:candidateEnd]
			if validators.ValidateIBAN(candidate).Valid {
				return candidateEnd
			}
		}
		return start
	}
	if rule.validator != "" && !validators.Validate(rule.validator, text[start:end]).Valid {
		return start
	}
	if rule.kind == "IP_ADDRESS" {
		prefix := strings.TrimRight(text[:start], " \t")
		if versionPrefix.MatchString(prefix) {
			return start
		}
		// Avoid extracting four components out of a longer dotted sequence.
		if start > 0 && text[start-1] == '.' || end < len(text) && text[end] == '.' && end+1 < len(text) && text[end+1] >= '0' && text[end+1] <= '9' {
			return start
		}
	}
	return end
}
