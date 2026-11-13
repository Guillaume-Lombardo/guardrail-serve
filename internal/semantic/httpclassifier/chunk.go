package httpclassifier

import "unicode"

// chunk is one piece of a scanned text.
type chunk struct {
	textIndex int
	text      string
}

// splitRunes splits text into windows of at most size runes where each window
// starts overlap runes before the previous one ended. It never cuts inside a
// UTF-8 sequence (it works on runes) and prefers cutting after whitespace,
// then outside a combining sequence, within the last size/4 runes of a
// window. A text no longer than size is returned unchanged. The caller
// guarantees 0 <= overlap <= size/4, which makes every window advance by at
// least size/2 runes. Splitting stops once limit chunks were produced and
// reports false, so oversized texts are never fully materialised.
func splitRunes(text string, size, overlap, limit int) (chunks []string, complete bool) {
	runes := []rune(text)
	if len(runes) <= size {
		return []string{text}, limit >= 1
	}

	start := 0
	for {
		end := start + size
		if end >= len(runes) {
			end = len(runes)
		} else {
			end = cutPoint(runes, start, end, size/4)
		}
		if len(chunks) == limit {
			return chunks, false
		}
		chunks = append(chunks, string(runes[start:end]))
		if end == len(runes) {
			return chunks, true
		}
		start = end - overlap
	}
}

// cutPoint moves end backwards by at most maxBack runes to a cleaner
// boundary, and returns end unchanged when none exists.
func cutPoint(runes []rune, start, end, maxBack int) int {
	floor := max(end-maxBack, start+1)
	for cut := end; cut >= floor; cut-- {
		if unicode.IsSpace(runes[cut-1]) {
			return cut
		}
	}
	for cut := end; cut >= floor; cut-- {
		if !continuesCluster(runes[cut-1], runes[cut]) {
			return cut
		}
	}
	return end
}

// continuesCluster reports whether next visually continues the sequence that
// ends with prev, so cutting between them would split a user-perceived
// character (combining marks, joiners, variation selectors, emoji modifiers).
func continuesCluster(prev, next rune) bool {
	return prev == '‍' || next == '‍' || unicode.IsMark(next) ||
		(next >= 0x1F3FB && next <= 0x1F3FF)
}
