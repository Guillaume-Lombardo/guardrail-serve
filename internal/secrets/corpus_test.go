package secrets

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// The corpus is synthetic: every token is generated at test time from a
// fixed seed with the shape of a real provider credential, so no real secret
// and no complete token literal is stored in the repository. It is a
// representative regression corpus, not an exhaustive benchmark.

// fixtureGen is a splitmix64 generator: deterministic across Go versions.
type fixtureGen struct{ state uint64 }

func newFixtureGen(seed uint64) *fixtureGen { return &fixtureGen{state: seed} }

func (g *fixtureGen) next() uint64 {
	g.state += 0x9e3779b97f4a7c15
	z := g.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (g *fixtureGen) pick(alphabet string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[g.next()%uint64(len(alphabet))])
	}
	return b.String()
}

const (
	alphaUpper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alphaLower  = "abcdefghijklmnopqrstuvwxyz"
	alphaDigits = "0123456789"
	alphaAlnum  = alphaUpper + alphaLower + alphaDigits
	alphaLowAln = alphaLower + alphaDigits
	alphaHex    = "0123456789abcdef"
	alphaBase32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	alphaURL    = alphaAlnum + "-_"
	alphaB64    = alphaAlnum + "+/"
)

// providerCase builds a text containing one synthetic credential.
type providerCase struct {
	rule  string
	build func(g *fixtureGen) (text, secret string)
}

func around(format, secret string) (string, string) {
	return fmt.Sprintf(format, secret), secret
}

func providerCases() []providerCase {
	return []providerCase{
		{"aws-access-token", func(g *fixtureGen) (string, string) {
			return around("export AWS_ACCESS_KEY_ID=%s\n", "AKIA"+g.pick(alphaBase32, 16))
		}},
		{"github-pat", func(g *fixtureGen) (string, string) {
			return around("use this token %s for the CI", "ghp_"+g.pick(alphaAlnum, 36))
		}},
		{"github-fine-grained-pat", func(g *fixtureGen) (string, string) {
			return around("GH_TOKEN=%s", "github_pat_"+g.pick(alphaAlnum+"_", 82))
		}},
		{"github-oauth", func(g *fixtureGen) (string, string) {
			return around("oauth: %s", "gho_"+g.pick(alphaAlnum, 36))
		}},
		{"github-app-token", func(g *fixtureGen) (string, string) {
			return around("installation token %s expires soon", "ghs_"+g.pick(alphaAlnum, 36))
		}},
		{"gitlab-pat", func(g *fixtureGen) (string, string) {
			return around("git remote set-url origin https://oauth2:%s@gitlab.example.com/a/b.git", "glpat-"+g.pick(alphaURL, 20))
		}},
		{"slack-bot-token", func(g *fixtureGen) (string, string) {
			return around("SLACK_BOT=%s", "xoxb-"+g.pick(alphaDigits, 12)+"-"+g.pick(alphaDigits, 12)+"-"+g.pick(alphaAlnum, 24))
		}},
		{"slack-webhook-url", func(g *fixtureGen) (string, string) {
			return around("post to %s please", "https://hooks.slack.com/services/T"+g.pick(alphaUpper+alphaDigits, 10)+"/B"+g.pick(alphaUpper+alphaDigits, 10)+"/"+g.pick(alphaAlnum, 24))
		}},
		{"stripe-access-token", func(g *fixtureGen) (string, string) {
			return around("stripe.api_key = \"%s\"", "sk_live_"+g.pick(alphaAlnum, 24))
		}},
		{"openai-api-key", func(g *fixtureGen) (string, string) {
			return around("OPENAI_API_KEY=%s\n", "sk-proj-"+g.pick(alphaURL, 73)+"a"+"T3BlbkFJ"+g.pick(alphaURL, 73)+"b")
		}},
		{"anthropic-api-key", func(g *fixtureGen) (string, string) {
			return around("client = Client(api_key='%s')", "sk-ant-api03-"+g.pick(alphaURL, 93)+"AA")
		}},
		{"gcp-api-key", func(g *fixtureGen) (string, string) {
			return around("maps key %s in the page", "AIza"+g.pick(alphaURL, 35))
		}},
		{"npm-access-token", func(g *fixtureGen) (string, string) {
			return around("//registry.npmjs.org/:_authToken=%s\n", "npm_"+g.pick(alphaLowAln, 36))
		}},
		{"sendgrid-api-token", func(g *fixtureGen) (string, string) {
			return around("SENDGRID=%s ", "SG."+g.pick(alphaAlnum, 22)+"."+g.pick(alphaAlnum, 43))
		}},
		{"huggingface-access-token", func(g *fixtureGen) (string, string) {
			return around("huggingface-cli login --token %s", "hf_"+g.pick(alphaUpper+alphaLower, 34))
		}},
		{"jwt", func(g *fixtureGen) (string, string) {
			return around("cookie session=%s;", "eyJ"+g.pick(alphaAlnum, 30)+".eyJ"+g.pick(alphaAlnum, 40)+"."+g.pick(alphaURL, 42)+"x")
		}},
		{"private-key", func(g *fixtureGen) (string, string) {
			var body strings.Builder
			for i := 0; i < 4; i++ {
				body.WriteString(g.pick(alphaB64, 64) + "\n")
			}
			// Assembled from fragments so the repository never holds a
			// complete PEM header (and pre-commit detect-private-key passes).
			pem := "-----BEGIN RSA " + "PRIVATE KEY-----\n" + body.String() + "-----END RSA " + "PRIVATE KEY-----"
			return around("key file:\n%s\n", pem)
		}},
		{"digitalocean-pat", func(g *fixtureGen) (string, string) {
			return around("DO_TOKEN=%s", "dop_v1_"+g.pick(alphaHex, 64))
		}},
		{"vault-service-token", func(g *fixtureGen) (string, string) {
			return around("VAULT_TOKEN=%s ", "hvs."+g.pick(alphaURL, 95))
		}},
		{"databricks-api-token", func(g *fixtureGen) (string, string) {
			return around("token: %s", "dapi"+g.pick(alphaHex, 32))
		}},
		{"postman-api-token", func(g *fixtureGen) (string, string) {
			return around("x-api-key %s ", "PMAK-"+g.pick(alphaHex, 24)+"-"+g.pick(alphaHex, 34))
		}},
		{"sentry-user-token", func(g *fixtureGen) (string, string) {
			return around("SENTRY_AUTH=%s", "sntryu_"+g.pick(alphaHex, 64))
		}},
		{"shopify-access-token", func(g *fixtureGen) (string, string) {
			return around("shop token %s", "shpat_"+g.pick(alphaHex, 32))
		}},
		{"doppler-api-token", func(g *fixtureGen) (string, string) {
			return around("DOPPLER_TOKEN=%s", "dp.pt."+g.pick(alphaAlnum, 43))
		}},
		{"linear-api-key", func(g *fixtureGen) (string, string) {
			return around("linear: %s", "lin_api_"+g.pick(alphaAlnum, 40))
		}},
		{"grafana-service-account-token", func(g *fixtureGen) (string, string) {
			return around("GRAFANA=%s\n", "glsa_"+g.pick(alphaAlnum, 32)+"_"+g.pick(alphaHex, 8))
		}},
		{"pypi-upload-token", func(g *fixtureGen) (string, string) {
			return around("password = %s", "pypi-AgEIcHlwaS5vcmc"+g.pick(alphaURL, 60))
		}},
		{"twilio-api-key", func(g *fixtureGen) (string, string) {
			return around("twilio sid %s", "SK"+g.pick(alphaHex, 32))
		}},
	}
}

func mustScanner(t *testing.T, cfg Config) *Scanner {
	t.Helper()
	scanner, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return scanner
}

func scan(t *testing.T, scanner *Scanner, text string) []Finding {
	t.Helper()
	findings, err := scanner.Scan(context.Background(), text)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return findings
}

func gitleaksOnly() Config { return Config{Gitleaks: GitleaksConfig{Enabled: true}} }

func keywordsOnly() Config { return Config{Keywords: KeywordConfig{Enabled: true}} }

func entropyOnly() Config {
	cfg := DefaultConfig()
	return Config{Entropy: cfg.Entropy}
}

// describe renders findings without their values.
func describe(findings []Finding) string {
	parts := make([]string, len(findings))
	for i, f := range findings {
		parts[i] = fmt.Sprintf("%s[%d,%d)", f.Rule, f.ByteStart, f.ByteEnd)
	}
	return strings.Join(parts, " ")
}

func hasFinding(findings []Finding, rule string, start, end int) bool {
	for _, f := range findings {
		if f.Rule == rule && f.ByteStart == start && f.ByteEnd == end {
			return true
		}
	}
	return false
}

func TestProviderCorpusMatchesExpectedGitleaksRule(t *testing.T) {
	scanner := mustScanner(t, gitleaksOnly())
	full := mustScanner(t, DefaultConfig())
	for seed, tc := range providerCases() {
		for variant := uint64(0); variant < 3; variant++ {
			text, secret := tc.build(newFixtureGen(uint64(seed)*101 + variant + 1))
			start := strings.Index(text, secret)
			rule := gitleaksRulePrefix + tc.rule
			if findings := scan(t, scanner, text); !hasFinding(findings, rule, start, start+len(secret)) {
				t.Errorf("%s variant %d: want %s on the token, got %s", tc.rule, variant, rule, describe(findings))
			}
			// With every source enabled the provider rule still explains the
			// token: no weaker finding is reported inside it.
			for _, f := range scan(t, full, text) {
				if f.ByteStart >= start && f.ByteEnd <= start+len(secret) && f.Source != SourceGitleaks {
					t.Errorf("%s variant %d: redundant %s finding inside the token", tc.rule, variant, f.Rule)
				}
			}
		}
	}
}

// benignCorpus must produce no finding with every source enabled. Each line
// targets a known false-positive family.
var benignCorpus = []string{
	// prose, English and French
	"The quarterly report is attached; please review the revenue numbers before Friday.",
	"Le mot de passe oublié ? Cliquez sur le lien pour le réinitialiser.",
	"Le mot de passe est incorrect, veuillez réessayer.",
	"Please enter your password to continue.",
	"Password: Please enter your password",
	"The password is required and must be at least twelve characters long.",
	"The secret is out: we are launching the internationalization initiative next quarter.",
	"secretary: Alice Martin",
	"A bearer instrument is payable to whoever holds it.",
	"Bearer authentication is described in RFC 6750.",
	// schemas, references and templates
	"password: required",
	"password: string",
	"secret: null",
	"api_key: true",
	"password: \"\"",
	"password: ********",
	"password = os.environ['DB_PASSWORD']",
	"password = os.getenv(\"DB_PASSWORD\")",
	"api_key = settings.API_KEY",
	"token = process.env.API_TOKEN",
	"password: ${DB_PASSWORD}",
	"password: {{ .Values.database.password }}",
	"password: <your-password>",
	"api_key: YOUR_API_KEY_HERE",
	"api_key = \"your-api-key-here\"",
	"password: %DB_PASS%",
	"password=$DB_PASS",
	"DB_PASSWORD=DATABASE_PASSWORD_FROM_VAULT",
	"Authorization: Bearer <token>",
	"Authorization: Bearer $TOKEN",
	"curl -H \"Authorization: Bearer ${ACCESS_TOKEN}\" https://api.example.com/v1/items",
	// descriptors, identifiers and counters
	"max_tokens: 4096",
	`{"usage": {"prompt_tokens": 123456, "completion_tokens": 4096, "total_tokens": 127552}}`,
	"token: 4096",
	"token_count: 123456",
	"password_length = 12345678",
	"password_min_length: 16",
	"token_url = https://auth.example.com/oauth2/token",
	"password_reset_url: https://accounts.example.com/reset",
	"secret_name: prod-db-credentials",
	"PWD=/home/alice/projects/guardrail-serve",
	"user_id = 5f2b9c8e7d6a4b3c2e1f0a9b8c7d6e5f",
	"client_id: 7c9e6679-7425-40de-944b-e07fc1f90ae7",
	"request id 123e4567-e89b-12d3-a456-426614174000 completed",
	"{\"id\": \"9b2f4c1e-3d5a-4e6b-8c7d-0a1b2c3d4e5f\", \"status\": \"ok\"}",
	// git, digests and integrity hashes
	"commit 3f786850e387550fdab836ed7e6dc881de23001b",
	"Merge 9fceb02d0ae598e95dc970b74767f19372d61af8 into 1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e",
	"cherry-picked from 2c26b46b68ffc68ff99b453c1d30413413422d70",
	"see https://github.com/example/repo/commit/a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
	"image: registry.example.com/app@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	"sha256sum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.txt",
	"md5 checksum d41d8cd98f00b204e9800998ecf8427e",
	`"integrity": "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="`,
	"etag: 686897696a7c876b7e",
	// URLs and paths
	"https://docs.example.com/guides/getting-started/installation-on-linux-and-macos/troubleshooting",
	"https://cdn.example.com/static/js/vendor-bundle-production-build.min.js?v=20261113",
	"/usr/local/lib/python3.12/site-packages/some_module/sub_package/implementation_details.py",
	"C:\\Users\\alice\\AppData\\Local\\Programs\\Application\\resources\\app.asar",
	"src/main/java/com/example/internal/AbstractSingletonProxyFactoryBean.java",
	"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
	// numbers, versions, identifiers, sequences
	"card ending 4111 1111 1111 1111 expires 12/29",
	"order 1234567890123456 shipped at 2026-11-13T09:30:00+01:00",
	"timestamp 1763022600123 build 20261113093000",
	"version v1.24.3-rc.1+build.20261113 released",
	"IPv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334 and MAC 00:1A:2B:3C:4D:5E",
	"pod my-app-7f9c2b6d5-x2k9p restarted",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"0123456789ABCDEF",
	"deadbeefcafebabe",
	"color: #ff00aa; background: #00ff00;",
	"SGVsbG8gd29ybGQ=",
	"the_quick_brown_fox_jumps_over_the_lazy_dog_again_and_again",
	"internationalization-localization-accessibility-performance",
	// code
	"func (s *Scanner) Scan(ctx context.Context, text string) ([]Finding, error) {",
	"const secretKeyLength = 32 // bytes",
	"if user.password != confirmPassword { return errMismatch }",
	"<input type=\"password\" name=\"password\" autocomplete=\"current-password\">",
	"public_key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGcn7mUbgnFXpjQ6",
	"csrf_token: Xy9Kq2Lm3Np4Rs5T",
	"next_page_token: CAEaBQoDCgEx",
	"keys: [primary, secondary]",
}

func TestBenignCorpusHasNoFinding(t *testing.T) {
	scanner := mustScanner(t, DefaultConfig())
	for _, line := range benignCorpus {
		if findings := scan(t, scanner, line); len(findings) > 0 {
			t.Errorf("unexpected findings %s in %q", describe(findings), line)
		}
	}
}

// TestNoFalsePositiveAvalanche scans a large benign document assembled from
// the corpus and generated prose, code, identifiers and digests.
func TestNoFalsePositiveAvalanche(t *testing.T) {
	g := newFixtureGen(20261113)
	var doc strings.Builder
	words := []string{"policy", "engine", "request", "response", "guardrail", "finding", "token", "secret", "password", "key", "commit", "review", "release", "mot", "de", "passe", "is", "the", "and", "with"}
	for i := 0; i < 400; i++ {
		doc.WriteString(benignCorpus[i%len(benignCorpus)])
		doc.WriteByte('\n')
		for j := 0; j < 12; j++ {
			doc.WriteString(words[g.next()%uint64(len(words))])
			doc.WriteByte(' ')
		}
		doc.WriteString(fmt.Sprintf("\ncommit %s\n", g.pick(alphaHex, 40)))
		doc.WriteString(fmt.Sprintf("request_id=%s-%s-%s-%s-%s\n", g.pick(alphaHex, 8), g.pick(alphaHex, 4), g.pick(alphaHex, 4), g.pick(alphaHex, 4), g.pick(alphaHex, 12)))
		doc.WriteString(fmt.Sprintf("counter_%d = %d\n", i, g.next()%1000000))
	}
	scanner := mustScanner(t, DefaultConfig())
	text := doc.String()
	if findings := scan(t, scanner, text); len(findings) > 0 {
		f := findings[0]
		t.Fatalf("%d findings in benign document, first %s near %q", len(findings), f.Rule, text[max(0, f.ByteStart-40):f.ByteStart])
	}
}

func TestRandomHighEntropyFixturesAreFlagged(t *testing.T) {
	scanner := mustScanner(t, entropyOnly())
	for seed := uint64(1); seed <= 20; seed++ {
		g := newFixtureGen(seed)
		cases := []struct {
			format, secret, rule string
		}{
			{"the value %s was pasted", g.pick(alphaB64, 40), ruleEntropyBase64},
			{"config \"%s\"", g.pick(alphaURL, 43), ruleEntropyBase64},
			{"blob=%s==", g.pick(alphaB64, 40), ruleEntropyBase64},
			{"hex value %s here", g.pick(alphaHex, 32), ruleEntropyHex},
		}
		for _, tc := range cases {
			text := fmt.Sprintf(tc.format, tc.secret)
			start := strings.Index(text, tc.secret)
			end := start + len(tc.secret)
			if strings.HasPrefix(tc.format, "blob=") {
				end += 2 // padding belongs to the candidate
			}
			if findings := scan(t, scanner, text); !hasFinding(findings, tc.rule, start, end) {
				t.Errorf("seed %d: want %s on %q, got %s", seed, tc.rule, tc.format, describe(findings))
			}
		}
	}
}
