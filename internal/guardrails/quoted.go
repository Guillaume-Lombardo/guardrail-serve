package guardrails

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/g1lom/guardrail-serve/internal/textnorm"
)

// maxQuotedBytes bounds one quotation: a long "quote" is content, not a mention.
const maxQuotedBytes = 400

// Cues are matched on the folded frame (the text outside quotations), which is
// lowercase and has no diacritics.
var (
	analysisCue = regexp.MustCompile(`\b(?:que\s+signifie|que\s+veut\s+dire|signification|analyse[rz]?|analysez|explique[rz]?|expliquant|traduis|traduire|traduisez|traduction|commente[rz]?|pourquoi|comment\s+(?:detecter|reperer|bloquer|filtrer|reconnaitre|eviter)|exemples?\s+(?:typiques?\s+)?d'(?:attaque|injection)|attaques?|injections?|citation|personnage|article|roman|what\s+does|explain|analy[sz]e|translate)\b`)
	// An execution request anywhere outside the quotations cancels the
	// exemption, unless that occurrence is negated ("sans l'executer", "ne
	// l'applique pas"): see executionRequested.
	executionCue = regexp.MustCompile(`\b(?:execute[rsz]?|applique[rsz]?|obei[rs]|obeissez|obeir|suis\s+(?:la|cette|ces|les|ses)|suivez|suivre|fais\s+ce\s+qu|faites\s+ce\s+qu|fais-(?:le|la)|faites-(?:le|la)|suis-(?:la|le|les)|agis|agissez|(?:mets?|mettez)(?:-(?:la|le|les))?\s+en\s+(?:pratique|oeuvre|application)|follow|obey|apply|comply|do\s+what)\b`)
	// negatedBefore matches the end of the frame just before an execution cue
	// when the cue is negated: "sans", "ne" or "n'", then up to three clitics
	// or negation adverbs.
	negatedBefore = regexp.MustCompile(`(?:^|[^\pL'])(?:sans|ne|n')\s*(?:(?:pas|jamais|surtout|plus|rien|l'|le|la|les|me|m'|lui|leur|y|en)\s*){0,3}$`)
)

// maxNegationBytes bounds the text inspected before each execution cue.
const maxNegationBytes = 48

// executionRequested reports whether the frame contains an execution cue that
// is not explicitly negated. One affirmative request is enough, even next to a
// negated one.
func executionRequested(frame string) bool {
	for _, cue := range executionCue.FindAllStringIndex(frame, -1) {
		before := frame[max(0, cue[0]-maxNegationBytes):cue[0]]
		for !utf8.ValidString(before) {
			before = before[1:]
		}
		if !negatedBefore.MatchString(before) {
			return true
		}
	}
	return false
}

var quotePairs = map[rune]rune{'«': '»', '“': '”', '"': '"'}

// quotedMentions returns the folded byte ranges inside paired quotation marks
// when the text outside every quotation asks to analyse, explain or translate
// and never to execute. A rule with exempt_quoted_analysis ignores a match that
// lies entirely inside one of these ranges: quoting an attack is not an attack.
// Unpaired or overlong quotations are never exempt.
func quotedMentions(folded *textnorm.Folded) []textnorm.Span {
	text := folded.Text()
	var quotes []textnorm.Span
	var frame strings.Builder
	last, open, closer := 0, -1, rune(0)
	for index, r := range text {
		switch {
		case open < 0:
			if c, ok := quotePairs[r]; ok {
				open, closer = index, c
			}
		case r == closer:
			inner := textnorm.Span{Start: open + utf8.RuneLen(quoteOpener(text[open:])), End: index}
			if inner.End-inner.Start <= maxQuotedBytes {
				quotes = append(quotes, inner)
				frame.WriteString(text[last:open])
				frame.WriteByte(' ')
				last = index + utf8.RuneLen(r)
			}
			open = -1
		}
	}
	frame.WriteString(text[last:])
	if len(quotes) == 0 || !analysisCue.MatchString(frame.String()) || executionRequested(frame.String()) {
		return nil
	}
	return quotes
}

func quoteOpener(s string) rune {
	r, _ := utf8.DecodeRuneInString(s)
	return r
}

func insideAny(spans []textnorm.Span, start, end int) bool {
	for _, span := range spans {
		if start >= span.Start && end <= span.End {
			return true
		}
	}
	return false
}
