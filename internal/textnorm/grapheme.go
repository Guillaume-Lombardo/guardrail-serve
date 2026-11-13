package textnorm

import (
	"bufio"
	_ "embed"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// The grapheme cluster tables come verbatim (trailing whitespace stripped)
// from the Unicode Character Database 15.0.0, the Unicode version used by the
// Go standard library and golang.org/x/text/unicode/norm in this module.

//go:embed ucd/GraphemeBreakProperty-15.0.0.txt
var graphemeBreakPropertyData string

//go:embed ucd/emoji-data-15.0.0.txt
var emojiData string

// graphemeUnicodeVersion is the Unicode version of the embedded tables.
const graphemeUnicodeVersion = "15.0.0"

// gcb is a Grapheme_Cluster_Break property value (UAX #29, table 2).
type gcb uint8

const (
	gcbOther gcb = iota
	gcbCR
	gcbLF
	gcbControl
	gcbExtend
	gcbZWJ
	gcbRegionalIndicator
	gcbPrepend
	gcbSpacingMark
	gcbL
	gcbV
	gcbT
	gcbLV
	gcbLVT
)

var gcbNames = map[string]gcb{
	"CR":                 gcbCR,
	"LF":                 gcbLF,
	"Control":            gcbControl,
	"Extend":             gcbExtend,
	"ZWJ":                gcbZWJ,
	"Regional_Indicator": gcbRegionalIndicator,
	"Prepend":            gcbPrepend,
	"SpacingMark":        gcbSpacingMark,
	"L":                  gcbL,
	"V":                  gcbV,
	"T":                  gcbT,
	"LV":                 gcbLV,
	"LVT":                gcbLVT,
}

type propRange struct {
	lo, hi rune
	value  gcb
}

type graphemeTables struct {
	breakProperty []propRange // sorted, non-overlapping
	pictographic  []propRange // Extended_Pictographic, sorted, non-overlapping
}

var (
	tablesOnce sync.Once
	tables     graphemeTables
)

func loadTables() *graphemeTables {
	tablesOnce.Do(func() {
		breakProperty, err := parseUCD(graphemeBreakPropertyData, func(name string) (gcb, bool) {
			value, ok := gcbNames[name]
			return value, ok
		})
		if err != nil {
			panic(fmt.Sprintf("textnorm: embedded GraphemeBreakProperty data: %v", err))
		}
		pictographic, err := parseUCD(emojiData, func(name string) (gcb, bool) {
			return gcbOther, name == "Extended_Pictographic"
		})
		if err != nil {
			panic(fmt.Sprintf("textnorm: embedded emoji data: %v", err))
		}
		tables = graphemeTables{breakProperty: breakProperty, pictographic: pictographic}
	})
	return &tables
}

// parseUCD reads "XXXX[..YYYY] ; Property # comment" lines and keeps the
// ranges whose property is accepted by keep.
func parseUCD(data string, keep func(string) (gcb, bool)) ([]propRange, error) {
	var ranges []propRange
	scanner := bufio.NewScanner(strings.NewReader(data))
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		codePoints, property, ok := strings.Cut(line, ";")
		if !ok {
			return nil, fmt.Errorf("line %d: missing property field", lineNumber)
		}
		value, keepIt := keep(strings.TrimSpace(property))
		if !keepIt {
			continue
		}
		loText, hiText, isRange := strings.Cut(strings.TrimSpace(codePoints), "..")
		lo, err := strconv.ParseUint(loText, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		hi := lo
		if isRange {
			if hi, err = strconv.ParseUint(hiText, 16, 32); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNumber, err)
			}
		}
		ranges = append(ranges, propRange{lo: rune(lo), hi: rune(hi), value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(ranges, func(a, b propRange) int { return int(a.lo - b.lo) })
	for index := 1; index < len(ranges); index++ {
		if ranges[index].lo <= ranges[index-1].hi {
			return nil, fmt.Errorf("overlapping ranges at U+%04X", ranges[index].lo)
		}
	}
	return ranges, nil
}

func lookup(ranges []propRange, r rune) (gcb, bool) {
	index, found := slices.BinarySearchFunc(ranges, r, func(item propRange, target rune) int {
		switch {
		case item.hi < target:
			return -1
		case item.lo > target:
			return 1
		}
		return 0
	})
	if !found {
		return gcbOther, false
	}
	return ranges[index].value, true
}

func (t *graphemeTables) property(r rune) gcb {
	if r >= 0x20 && r < 0x7f {
		return gcbOther
	}
	value, _ := lookup(t.breakProperty, r)
	return value
}

func (t *graphemeTables) isPictographic(r rune) bool {
	if r < 0xa9 {
		return false
	}
	_, found := lookup(t.pictographic, r)
	return found
}

// graphemeBreaks reports, for each index i in [0, len(runes)], whether an
// extended grapheme cluster boundary exists before runes[i], following the
// UAX #29 rules GB1-GB999 for Unicode 15.0.0.
func graphemeBreaks(runes []rune) []bool {
	t := loadTables()
	breaks := make([]bool, len(runes)+1)
	if len(runes) == 0 {
		breaks[0] = true
		return breaks
	}
	breaks[0], breaks[len(runes)] = true, true // GB1, GB2

	previous := t.property(runes[0])
	// pictographicRun is true while the text before the current position
	// matches ExtPict Extend* (GB11 left context, before the ZWJ).
	pictographicRun := t.isPictographic(runes[0])
	// zwjAfterPictographic is true when the previous rune is a ZWJ that
	// follows ExtPict Extend*.
	zwjAfterPictographic := false
	regionalIndicators := 0
	if previous == gcbRegionalIndicator {
		regionalIndicators = 1
	}

	for index := 1; index < len(runes); index++ {
		current := t.property(runes[index])
		pictographic := t.isPictographic(runes[index])
		breaks[index] = isBreak(previous, current, pictographic, zwjAfterPictographic, regionalIndicators)

		zwjAfterPictographic = current == gcbZWJ && pictographicRun
		switch {
		case pictographic:
			pictographicRun = true
		case current == gcbExtend && pictographicRun:
		default:
			pictographicRun = false
		}
		if current == gcbRegionalIndicator {
			regionalIndicators++
		} else {
			regionalIndicators = 0
		}
		previous = current
	}
	return breaks
}

func isBreak(previous, current gcb, currentPictographic, zwjAfterPictographic bool, regionalIndicators int) bool {
	switch {
	case previous == gcbCR && current == gcbLF: // GB3
		return false
	case previous == gcbControl || previous == gcbCR || previous == gcbLF: // GB4
		return true
	case current == gcbControl || current == gcbCR || current == gcbLF: // GB5
		return true
	case previous == gcbL && (current == gcbL || current == gcbV || current == gcbLV || current == gcbLVT): // GB6
		return false
	case (previous == gcbLV || previous == gcbV) && (current == gcbV || current == gcbT): // GB7
		return false
	case (previous == gcbLVT || previous == gcbT) && current == gcbT: // GB8
		return false
	case current == gcbExtend || current == gcbZWJ: // GB9
		return false
	case current == gcbSpacingMark: // GB9a
		return false
	case previous == gcbPrepend: // GB9b
		return false
	case previous == gcbZWJ && zwjAfterPictographic && currentPictographic: // GB11
		return false
	case previous == gcbRegionalIndicator && current == gcbRegionalIndicator: // GB12, GB13
		return regionalIndicators%2 == 0
	}
	return true // GB999
}
