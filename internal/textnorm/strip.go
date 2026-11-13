package textnorm

// IsStripped reports whether r is removed by Normalize. The set is closed and
// explicit; every other code point, including letters of any script, is kept
// (subject to NFKC).
//
// Invisible formatting characters (zero width or default-invisible in running
// text):
//
//	U+00AD SOFT HYPHEN
//	U+180E MONGOLIAN VOWEL SEPARATOR
//	U+200B ZERO WIDTH SPACE
//	U+200C ZERO WIDTH NON-JOINER
//	U+200D ZERO WIDTH JOINER
//	U+2060 WORD JOINER
//	U+2061 FUNCTION APPLICATION .. U+2064 INVISIBLE PLUS
//	U+FEFF ZERO WIDTH NO-BREAK SPACE (byte order mark)
//
// Bidirectional formatting controls:
//
//	U+061C ARABIC LETTER MARK
//	U+200E LEFT-TO-RIGHT MARK
//	U+200F RIGHT-TO-LEFT MARK
//	U+202A LEFT-TO-RIGHT EMBEDDING .. U+202E RIGHT-TO-LEFT OVERRIDE
//	U+2066 LEFT-TO-RIGHT ISOLATE .. U+2069 POP DIRECTIONAL ISOLATE
func IsStripped(r rune) bool {
	switch {
	case r < 0x00ad:
		return false
	case r == 0x00ad, r == 0x061c, r == 0x180e, r == 0xfeff:
		return true
	case r >= 0x200b && r <= 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2060 && r <= 0x2064:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
