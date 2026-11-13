package secrets

import (
	"context"
	"math"
	"strings"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	cases := map[string]float64{
		"":                 0,
		"aaaa":             0,
		"ab":               1,
		"abcd":             2,
		"0123456789abcdef": 4,
		"aabbccddeeffgghh": 3,
	}
	for input, want := range cases {
		if got := shannonEntropy(input); math.Abs(got-want) > 1e-12 {
			t.Errorf("shannonEntropy(%q) = %v, want %v", input, got, want)
		}
	}
	if got := shannonEntropy("éé€€"); got != 1 {
		t.Errorf("entropy must count code points, got %v", got)
	}
}

func TestHexDigitAdjustment(t *testing.T) {
	// detect-secrets: all-digit strings lose 1.2/log2(len) bits.
	digits := "12345678901234567890"
	want := shannonEntropy(digits) - 1.2/math.Log2(20)
	if got := hexEntropyAdjust(digits, shannonEntropy(digits)); math.Abs(got-want) > 1e-12 {
		t.Errorf("adjusted entropy = %v, want %v", got, want)
	}
	if got := hexEntropyAdjust("1a", 1); got != 1 {
		t.Errorf("non-numeric hex must not be adjusted, got %v", got)
	}
}

// distinct returns n distinct characters of alphabet in a non-sequential
// order (the sequential filter is tested separately).
func distinct(alphabet string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[(i*7)%len(alphabet)])
	}
	return b.String()
}

func TestEntropyThresholdEdges(t *testing.T) {
	scanner := mustScanner(t, entropyOnly())
	const b64 = "aZ3kQ9mX2pL7vN5sR8tW4yB6cD1fG0hJ"
	// 23 distinct characters: log2(23) = 4.52 > 4.5.
	above := distinct(b64, 23)
	// 22 distinct characters: log2(22) = 4.46 <= 4.5.
	below := distinct(b64, 22)
	if math.Abs(shannonEntropy(above)-math.Log2(23)) > 1e-12 || len(distinctRunes(above)) != 23 {
		t.Fatalf("fixture %q is not 23 distinct characters", above)
	}
	if findings := scan(t, scanner, "v "+above+" end"); !hasFinding(findings, ruleEntropyBase64, 2, 25) {
		t.Errorf("base64 above threshold not reported: %s", describe(findings))
	}
	if findings := scan(t, scanner, "v "+below+" end"); len(findings) != 0 {
		t.Errorf("base64 below threshold reported: %s", describe(findings))
	}

	// Hex: 8 distinct characters twice = exactly 3.0 bits, which is not
	// strictly above the threshold; 9 distinct characters = 3.125 bits.
	exact := "a3f7c1e9" + "9e1c7f3a"
	if got := shannonEntropy(exact); got != 3 {
		t.Fatalf("fixture entropy %v, want 3", got)
	}
	if findings := scan(t, scanner, "hex "+exact); len(findings) != 0 {
		t.Errorf("hex at exactly 3.0 bits reported: %s", describe(findings))
	}
	over := "a3f7c1e9" + "9e1c7f3b" // b replaces one a
	if findings := scan(t, scanner, "hex "+over); !hasFinding(findings, ruleEntropyHex, 4, 20) {
		t.Errorf("hex above threshold not reported: %s", describe(findings))
	}
	if score := scan(t, scanner, "hex "+over)[0].Score; score == nil || *score != shannonEntropy(over) {
		t.Errorf("entropy findings must carry their score")
	}
}

func distinctRunes(s string) map[rune]bool {
	set := map[rune]bool{}
	for _, r := range s {
		set[r] = true
	}
	return set
}

func TestEntropyMinimumLengths(t *testing.T) {
	cfg := entropyOnly()
	cfg.Entropy.MinHexLength = 24
	scanner := mustScanner(t, cfg)
	g := newFixtureGen(7)
	short := g.pick(alphaHex, 20)
	if findings := scan(t, scanner, "hex "+short); len(findings) != 0 {
		t.Errorf("hex shorter than the configured minimum reported: %s", describe(findings))
	}
	long := g.pick(alphaHex, 24)
	if findings := scan(t, scanner, "hex "+long); len(findings) != 1 {
		t.Errorf("hex at the configured minimum not reported: %s", describe(findings))
	}
}

func TestEntropyFilters(t *testing.T) {
	g := newFixtureGen(42)
	secretHex40 := g.pick(alphaHex, 40)
	secretB64 := g.pick(alphaB64, 40)
	uuid := g.pick(alphaHex, 8) + "-" + g.pick(alphaHex, 4) + "-" + g.pick(alphaHex, 4) + "-" + g.pick(alphaHex, 4) + "-" + g.pick(alphaHex, 12)
	scanner := mustScanner(t, entropyOnly())
	cases := []struct {
		name   string
		text   string
		secret string // "" means no finding
	}{
		{"bare git SHA", "fixed in " + secretHex40, ""},
		{"git SHA in URL", "https://git.example.com/o/r/commit/" + secretHex40, ""},
		{"short SHA after commit", "commit " + secretHex40[:20], ""},
		{"digest word", "sha256: " + g.pick(alphaHex, 64), ""},
		{"strong context beats SHA shape", "api_key = " + secretHex40, secretHex40},
		{"strong context in JSON", `{"client_secret": "` + secretHex40 + `"}`, secretHex40},
		{"mixed case 40 hex is not a SHA", "value " + strings.ToUpper(secretHex40[:20]) + secretHex40[20:], strings.ToUpper(secretHex40[:20]) + secretHex40[20:]},
		{"uuid", "id " + uuid, ""},
		{"uuid with strong context", "api_key: " + uuid, ""}, // below 4.5 bits anyway
		{"identifier key", "user_id = " + g.pick(alphaHex, 32), ""},
		{"identifier key with base64", "tenantId: " + secretB64, ""},
		{"templated", "{" + secretB64 + "}", ""},
		{"dollar prefixed", "$" + secretB64, ""},
		{"data URI", "data:application/octet-stream;base64," + secretB64, ""},
		{"subresource integrity", "integrity sha384-" + secretB64, ""},
		{"sequential", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/", ""},
		{"digits only", "n 9182736450918273645091827364509182", ""},
		{"URL segment", "https://cdn.example.com/files/" + secretB64 + "/download", secretB64},
		{"quoted", `token("` + secretB64 + `")`, secretB64},
		{"assignment splits key", "blob=" + secretB64, secretB64},
		{"leading slash base64", "value /" + secretB64[1:], "/" + secretB64[1:]},
	}
	for _, tc := range cases {
		findings := scan(t, scanner, tc.text)
		if tc.secret == "" {
			if len(findings) != 0 {
				t.Errorf("%s: unexpected %s", tc.name, describe(findings))
			}
			continue
		}
		start := strings.Index(tc.text, tc.secret)
		if len(findings) != 1 || findings[0].ByteStart != start || findings[0].ByteEnd != start+len(tc.secret) {
			t.Errorf("%s: want one finding on the secret, got %s", tc.name, describe(findings))
		}
	}
}

func TestSplitPadding(t *testing.T) {
	text := "a=bc==d=="
	got := splitPadding(text, 0, len(text))
	want := [][2]int{{0, 1}, {2, 4}, {6, 9}}
	if len(got) != len(want) {
		t.Fatalf("splitPadding = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitPadding = %v, want %v", got, want)
		}
	}
}

func TestSpanIndex(t *testing.T) {
	index := newSpanIndex([][]int{{10, 20}, {0, 5}, {18, 25}, {25, 30}, {40, 50}})
	if want := (spanIndex{{0, 5}, {10, 30}, {40, 50}}); len(index) != len(want) || index[0] != want[0] || index[1] != want[1] || index[2] != want[2] {
		t.Fatalf("newSpanIndex = %v, want %v", index, want)
	}
	overlaps := map[[2]int]bool{{0, 1}: true, {4, 6}: true, {5, 10}: false, {29, 31}: true, {30, 40}: false, {49, 60}: true, {50, 60}: false}
	for span, want := range overlaps {
		if got := index.overlaps(span[0], span[1]); got != want {
			t.Errorf("overlaps(%v) = %v, want %v", span, got, want)
		}
	}
	contains := map[[2]int]bool{{0, 5}: true, {1, 6}: false, {10, 30}: true, {12, 28}: true, {30, 41}: false, {40, 50}: true, {45, 51}: false}
	for span, want := range contains {
		if got := index.contains(span[0], span[1]); got != want {
			t.Errorf("contains(%v) = %v, want %v", span, got, want)
		}
	}
	if newSpanIndex(nil).overlaps(0, 1) || newSpanIndex(nil).contains(0, 1) {
		t.Error("empty index matches")
	}
}

// Adversarial shapes that used to be quadratic (assignment and overlap
// lookups). Run with -bench to compare sizes; costs must grow linearly.
func BenchmarkAdversarialInputs(b *testing.B) {
	scanner, err := New(DefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	inputs := map[string]string{
		"assignments":   strings.Repeat("x=1\n", 16<<10),
		"passwords":     strings.Repeat("password=hunter2\n", 4<<10),
		"chain":         "x=" + strings.Repeat("a=", 32<<10),
		"base64":        strings.Repeat("aZ3kQ9mX2pL7vN5sR8tW4yB6cD1fG0hJ", 2<<10),
		"authorization": strings.Repeat("authorization:basic<", 4<<10),
		"nestedAuth":    strings.Repeat("x=authorization=basic&", 4<<10),
	}
	for name, text := range inputs {
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := scanner.Scan(context.Background(), text); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
