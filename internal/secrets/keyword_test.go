package secrets

import (
	"reflect"
	"strings"
	"testing"
)

// contextValue is a synthetic low-entropy password: only its context makes it
// a secret.
const contextValue = "Zx9!kQ2#mR"

func TestContextualSecretVariants(t *testing.T) {
	scanner := mustScanner(t, keywordsOnly())
	cases := []struct {
		format string
		rule   string
	}{
		{"password=%s", "keyword:password"},
		{"password = %s", "keyword:password"},
		{"password: %s", "keyword:password"},
		{"password : %s", "keyword:password"},
		{"mot de passe : %s", "keyword:password"},
		{"password：%s", "keyword:password"},
		{`"password": "%s"`, "keyword:password"},
		{`{'password': '%s'}`, "keyword:password"},
		{"PASSWORD=%s", "keyword:password"},
		{"PassWord=%s", "keyword:password"},
		{"Pwd=%s", "keyword:password"},
		{"PASSWD=%s", "keyword:password"},
		{"db_password=%s", "keyword:password"},
		{"dbPassword=%s", "keyword:password"},
		{"DB-PASSWORD2=%s", "keyword:password"},
		{"db_pass=%s", "keyword:password"},
		{"spring.datasource.password=%s", "keyword:password"},
		{"--password=%s", "keyword:password"},
		{"https://example.com/login?user=alice&password=%s&next=/", "keyword:password"},
		{`password := "%s"`, "keyword:password"},
		{`$password => '%s'`, "keyword:password"},
		{`if (password == "%s") {`, "keyword:password"},
		{"<password>%s</password>", "keyword:password"},
		{"the password is %s", "keyword:password"},
		{"the password is %s.", "keyword:password"},
		{"le mot de passe est %s", "keyword:password"},
		{"mdp=%s", "keyword:password"},
		{"contraseña: %s", "keyword:password"},
		{"client_secret=%s", "keyword:secret"},
		{"SECRET_KEY = '%s'", "keyword:secret"},
		{"clientSecret: %s", "keyword:secret"},
		{"api-key: %s", "keyword:api_key"},
		{"X-API-Key: %s", "keyword:api_key"},
		{`apiKey: "%s"`, "keyword:api_key"},
		{"private_key=%s", "keyword:api_key"},
		{"AUTH_TOKEN=%s", "keyword:token"},
		{"access_token: %s", "keyword:token"},
		{"credentials: %s", "keyword:credential"},
		{"Authorization: Basic %s", "keyword:authorization"},
		{`{\"password\":\"%s\"}`, "keyword:password"},
		{`"{\"db\": {\"password\": \"%s\"}}"`, "keyword:password"},
		{"adminPassword: %s", "keyword:password"},
		{"**Password:** %s", "keyword:password"},
		{"**Password**: %s", "keyword:password"},
		{"My password is: %s", "keyword:password"},
		{"Le mot de passe est : %s", "keyword:password"},
		{"passwordProd=%s", "keyword:password"},
		{`"Authorization": "Token %s"`, "keyword:authorization"},
	}
	for _, tc := range cases {
		text := strings.Replace(tc.format, "%s", contextValue, 1)
		start := strings.Index(text, contextValue)
		if findings := scan(t, scanner, text); !hasFinding(findings, tc.rule, start, start+len(contextValue)) {
			t.Errorf("%q: want %s on the value, got %s", tc.format, tc.rule, describe(findings))
		}
	}
}

func TestBearerCredential(t *testing.T) {
	scanner := mustScanner(t, keywordsOnly())
	token := "kQ2mR7xZ9pL4vN8s.Tw3"
	for _, format := range []string{
		"Authorization: Bearer %s",
		`curl -H "Authorization: Bearer %s" https://api.example.com`,
		"use bearer %s for the call",
	} {
		text := strings.Replace(format, "%s", token, 1)
		start := strings.Index(text, token)
		findings := scan(t, scanner, text)
		if len(findings) != 1 || findings[0].ByteStart != start || findings[0].ByteEnd != start+len(token) {
			t.Errorf("%q: want one finding on the token, got %s", format, describe(findings))
		}
	}
	if findings := scan(t, scanner, "bearer short1"); len(findings) != 0 {
		t.Errorf("short bearer value reported: %s", describe(findings))
	}
}

func TestDigitOnlyValues(t *testing.T) {
	scanner := mustScanner(t, keywordsOnly())
	if findings := scan(t, scanner, "pin password: 84736291"); len(findings) != 1 {
		t.Errorf("numeric password must be reported, got %s", describe(findings))
	}
	for _, text := range []string{"token: 84736291", "api_key = 84736291", "secret: 84736291"} {
		if findings := scan(t, scanner, text); len(findings) != 0 {
			t.Errorf("%q: numeric non-password value reported: %s", text, describe(findings))
		}
	}
}

func TestKeyTokens(t *testing.T) {
	cases := map[string][]string{
		"DB_PASSWORD2":                 {"db", "password"},
		"clientSecret":                 {"client", "secret"},
		"APIKey":                       {"api", "key"},
		"x-api-key":                    {"x", "api", "key"},
		"spring.datasource.password":   {"spring", "datasource", "password"},
		"mot de passe":                 {"mot", "de", "passe"},
		"--password":                   {"password"},
		"HTTPServerAuthorizationToken": {"http", "server", "authorization", "token"},
	}
	for key, want := range cases {
		if got := keyTokens(key); !reflect.DeepEqual(got, want) {
			t.Errorf("keyTokens(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestClassifyKey(t *testing.T) {
	cases := []struct {
		key    string
		group  string
		idLike bool
	}{
		{"password", groupPassword, false},
		{"newpassword", groupPassword, false},
		{"dbpass", groupPassword, false},
		{"MOT_DE_PASSE", groupPassword, false},
		{"secrets", groupSecret, false},
		{"appsecret", groupSecret, false},
		{"secretary", "", false},
		{"apikey", groupAPIKey, false},
		{"SECRET_KEY", groupSecret, false},
		{"key", "", false},
		{"monkey", "", false},
		{"accessToken", groupToken, false},
		{"tokens", "", false},
		{"max_tokens", "", false},
		{"csrf_token", "", false},
		{"public_key", "", false},
		{"password_length", "", false},
		{"token_url", "", false},
		{"secret_name", "", false},
		{"api_key_id", "", true},
		{"client_id", "", true},
		{"userid", "", true},
		{"request_id", "", true},
		{"Authorization", groupAuthorization, false},
		{"creds", groupCredential, false},
		{"PassWord", groupPassword, false},
		{"csrfToken", "", false},
		{"nextPageToken", "", false},
		{"apiKeyId", "", true},
		{"passwordHint", "", false},
		{"adminPassword", groupPassword, false},
		{"adminpassword", groupPassword, false},
		{"adminToken", groupToken, false},
		{"homepageToken", groupToken, false},
		{"nextpagetoken", "", false},
		{"maxTotalTokens", "", false},
		{"passwordProd", groupPassword, false},
		{"secretValue", groupSecret, false},
		{"apiKeyValue", groupAPIKey, false},
		{"accessTokenExpiry", "", false},
		{"secretArn", "", false},
		{"myNextPageToken", "", false},
		{"getCsrfToken", "", false},
		{"MinIOPassword", groupPassword, false},
		{"MinIOSecret", groupSecret, false},
		{"MinIOToken", groupToken, false},
		{"min_io_password", groupPassword, false},
		{"public_api_key", "", false},
		{"x_csrf_token", "", false},
		{"pageToken", "", false},
		{"nextPassword", groupPassword, false},
		{"nextpassword", groupPassword, false},
	}
	for _, tc := range cases {
		group, idLike := classifyKey(tc.key)
		if group != tc.group || idLike != tc.idLike {
			t.Errorf("classifyKey(%q) = (%q, %v), want (%q, %v)", tc.key, group, idLike, tc.group, tc.idLike)
		}
	}
}

func TestKeywordValueFilters(t *testing.T) {
	cases := []struct {
		value  string
		quoted bool
		group  string
		want   bool
	}{
		{"hunter2", false, groupPassword, true},
		{"hunt", true, groupPassword, true},
		{"hun", true, groupPassword, false},
		{"hunt2", false, groupPassword, false},
		{"Summer", false, groupPassword, false},
		{"summer", true, groupPassword, true},
		{"aBcdefg", false, groupPassword, true},
		{"well-known", false, groupPassword, false},
		{"REDACTED", true, groupPassword, false},
		{"[hidden]", true, groupPassword, false},
		{"xxxxxxxx", true, groupPassword, false},
		{"${DB_PASS}", true, groupPassword, false},
		{"{{ secret }}", true, groupPassword, false},
		{"%(password)s", true, groupPassword, false},
		{"$DB_PASS", true, groupPassword, false},
		{"your_token_here", true, groupToken, false},
		{"DB_PASSWORD", false, groupPassword, false},
		{"DB_PASSWORD", true, groupPassword, true},
		{"config.secret", false, groupSecret, false},
		{"/etc/app/secret", false, groupSecret, false},
		{"https://vault/x", false, groupSecret, false},
		{"!!!!!!!", true, groupPassword, false},
		{"$ecret123", true, groupPassword, true},
		{"<Tr0ub4dor&3x>", true, groupPassword, true},
		{"%Tr0ub4dor&3x%", true, groupPassword, true},
		{"<your password>", true, groupPassword, false},
		{"pass", true, groupPassword, false},
		{"Zx9!kQ2#mR", false, groupPassword, true},
	}
	for _, tc := range cases {
		if got := acceptKeywordValue(tc.value, 0, len(tc.value), tc.quoted, tc.group); got != tc.want {
			t.Errorf("acceptKeywordValue(%q, quoted=%v) = %v, want %v", tc.value, tc.quoted, got, tc.want)
		}
	}
	if acceptKeywordValue("get_secret()", 0, len("get_secret"), false, groupSecret) {
		t.Error("indirect reference get_secret() accepted")
	}
}

func TestNestedSecretAssignments(t *testing.T) {
	scanner := mustScanner(t, keywordsOnly())
	for _, format := range []string{
		"Here is password=%s",
		"note: password=%s",
		"note:password=%s",
		`note: "password=%s"`,
		`{"msg": "the password is %s"}`,
		"a=b=c=d=password=%s",
		"see https://example.com/login?password=%s",
		`Here is password="%s"`,
		"Here is password = %s",
		`Here is password = "%s"`,
		`note: x=password="%s"`,
	} {
		text := strings.Replace(format, "%s", contextValue, 1)
		start := strings.Index(text, contextValue)
		if findings := scan(t, scanner, text); !hasFinding(findings, "keyword:password", start, start+len(contextValue)) {
			t.Errorf("%q: want keyword:password on the value, got %s", format, describe(findings))
		}
	}
	for _, text := range []string{"a=b=c=d", "ratio=a:b:c", "x=" + strings.Repeat("a=", 2000)} {
		if findings := scan(t, scanner, text); len(findings) != 0 {
			t.Errorf("%.40q: unexpected %s", text, describe(findings))
		}
	}
}

func TestQuotedValuesHonourEscapes(t *testing.T) {
	scanner := mustScanner(t, keywordsOnly())
	for _, tc := range []struct{ text, value string }{
		{`{"password":"abc\"def123"}`, `abc\"def123`},
		{`{'password': 'it\'s9more'}`, `it\'s9more`},
		{`{"password":"abc\\"}`, `abc\\`},
		{`{"payload":"{\"password\":\"abc\\\"def123\"}"}`, `abc\\\"def123`},
		{`{"payload":"{\"password\":\"abc\\\\\"}"}`, `abc\\\\`},
	} {
		start := strings.Index(tc.text, tc.value)
		if findings := scan(t, scanner, tc.text); len(findings) != 1 || !hasFinding(findings, "keyword:password", start, start+len(tc.value)) {
			t.Errorf("%q: want one finding on the whole value, got %s", tc.text, describe(findings))
		}
	}
}

func TestURLCredentials(t *testing.T) {
	scanner := mustScanner(t, keywordsOnly())
	const password = "Zx9!kQ2mR7" // '#' would end the URL authority
	for _, format := range []string{
		"https://admin:%s@db.internal/x",
		"postgres://app:%s@10.0.0.1:5432/db",
		"connect to redis://:%s@cache:6379",
	} {
		text := strings.Replace(format, "%s", password, 1)
		start := strings.Index(text, password)
		if findings := scan(t, scanner, text); !hasFinding(findings, "keyword:url_credential", start, start+len(password)) {
			t.Errorf("%q: want keyword:url_credential on the password, got %s", format, describe(findings))
		}
	}
	for _, text := range []string{
		"https://user:pass@example.com/",
		"https://user:${DB_PASSWORD}@example.com/",
		"https://user:****@example.com/",
		"https://example.com:8443/path",
		"https://example.com:8080@foo",
		"mailto:someone@example.com",
	} {
		if findings := scan(t, scanner, text); len(findings) != 0 {
			t.Errorf("%q: unexpected %s", text, describe(findings))
		}
	}
}

func TestUnquotedValueSpans(t *testing.T) {
	scanner := mustScanner(t, keywordsOnly())
	for _, tc := range []struct{ text, value string }{
		{"password=Tr0ub4dor&3xyzQ", "Tr0ub4dor&3xyzQ"},
		{"password=Xk9mQ2;vL7zzz now", "Xk9mQ2;vL7zzz"},
		{"PASSWORD=Xk9mQ2vL7; export PASSWORD", "Xk9mQ2vL7"},
		{"https://x.example/login?password=Xk9mQ2vL7&next=/home", "Xk9mQ2vL7"},
		{"connect(password=Xk9mQ2vL7, user=bob)", "Xk9mQ2vL7"},
		{"f(password=Xk9mQ2vL7)", "Xk9mQ2vL7"},
		{"password=Xk9{mQ2}vL7", "Xk9{mQ2}vL7"},
		{"<password>Xk9mQ2vL7</password>", "Xk9mQ2vL7"},
	} {
		start := strings.Index(tc.text, tc.value)
		if findings := scan(t, scanner, tc.text); len(findings) != 1 || !hasFinding(findings, "keyword:password", start, start+len(tc.value)) {
			t.Errorf("%q: want one finding on %q, got %s", tc.text, tc.value, describe(findings))
		}
	}
}

func TestCodeReferencesAreNotSecrets(t *testing.T) {
	scanner := mustScanner(t, keywordsOnly())
	for _, text := range []string{
		"const body = { clientSecret: clientSecret };",
		"accessToken: accessToken,",
		"refreshToken: newRefreshToken",
		"password: hashedPassword,",
		"secretKey = secretKey ?? fallbackKey",
		"showPassword = !showPassword",
		"token: nextValue,",
		"const apiKey = config.apiKey;",
	} {
		if findings := scan(t, scanner, text); len(findings) != 0 {
			t.Errorf("%q: unexpected %s", text, describe(findings))
		}
	}
	for _, text := range []string{"password: hunter2Go", "password: !Abc123x", "nextPassword=Xk9mQ2vL7"} {
		if findings := scan(t, scanner, text); len(findings) != 1 {
			t.Errorf("%q: want one finding, got %s", text, describe(findings))
		}
	}
}
