package textnorm

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

func TestEmbeddedTablesMatchNormalizationUnicodeVersion(t *testing.T) {
	if graphemeUnicodeVersion != norm.Version {
		t.Fatalf("grapheme tables are Unicode %s but x/text norm is %s: refresh ucd/", graphemeUnicodeVersion, norm.Version)
	}
	if graphemeUnicodeVersion != unicode.Version {
		t.Fatalf("grapheme tables are Unicode %s but the Go unicode package is %s: refresh ucd/", graphemeUnicodeVersion, unicode.Version)
	}
}

// TestGraphemeBreaksConformance runs the official UAX #29 conformance file
// (GraphemeBreakTest-15.0.0.txt) against graphemeBreaks.
func TestGraphemeBreaksConformance(t *testing.T) {
	file, err := os.Open("testdata/GraphemeBreakTest-" + graphemeUnicodeVersion + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	cases := 0
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var runes []rune
		var want []bool
		for _, field := range fields {
			switch field {
			case "\u00f7":
				want = append(want, true)
			case "\u00d7":
				want = append(want, false)
			default:
				value, err := strconv.ParseUint(field, 16, 32)
				if err != nil {
					t.Fatalf("line %d: %v", lineNumber, err)
				}
				runes = append(runes, rune(value))
			}
		}
		if len(want) != len(runes)+1 {
			t.Fatalf("line %d: malformed test case", lineNumber)
		}
		got := graphemeBreaks(runes)
		for index := range want {
			if got[index] != want[index] {
				t.Errorf("line %d: break before index %d = %v, want %v (%s)", lineNumber, index, got[index], want[index], strings.TrimSpace(line))
				break
			}
		}
		cases++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if cases < 600 {
		t.Fatalf("only %d conformance cases parsed", cases)
	}
}

func TestGraphemeBreaksEmpty(t *testing.T) {
	if got := graphemeBreaks(nil); len(got) != 1 || !got[0] {
		t.Fatalf("graphemeBreaks(nil) = %v, want [true]", got)
	}
}

func TestParseUCDRejectsMalformedData(t *testing.T) {
	keepAll := func(string) (gcb, bool) { return gcbOther, true }
	for name, data := range map[string]string{
		"missing property": "0041\n",
		"bad code point":   "ZZZZ ; Extend\n",
		"bad range end":    "0041..ZZZZ ; Extend\n",
		"overlap":          "0041..0045 ; Extend\n0043 ; Extend\n",
	} {
		if _, err := parseUCD(data, keepAll); err == nil {
			t.Errorf("%s: parseUCD succeeded, want error", name)
		}
	}
}
