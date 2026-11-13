package validators

import (
	"strings"
	"testing"
)

// All fixtures are synthetic or published examples (card scheme test numbers,
// SWIFT IBAN Registry examples, identifiers printed in INSEE documentation);
// none identifies a person.

type fixture struct {
	name  string
	value string
	want  Reason
}

func runFixtures(t *testing.T, validate func(string) Result, fixtures []fixture) {
	t.Helper()
	for _, test := range fixtures {
		t.Run(test.name, func(t *testing.T) {
			got := validate(test.value)
			if got.Reason != test.want {
				t.Fatalf("Reason = %q, want %q", got.Reason, test.want)
			}
			if got.Valid != (test.want == ReasonValid) {
				t.Fatalf("Valid = %v with Reason %q", got.Valid, got.Reason)
			}
		})
	}
}

func TestSeparatorRule(t *testing.T) {
	tests := []struct {
		value   string
		letters bool
		want    string
		reason  Reason
	}{
		{"", false, "", ReasonEmpty},
		{"1234", false, "1234", ReasonValid},
		{"12 34-56", false, "123456", ReasonValid},
		{"1 2 3 4", false, "1234", ReasonValid},
		{" 1234", false, "", ReasonInvalidFormat},
		{"1234-", false, "", ReasonInvalidFormat},
		{"12  34", false, "", ReasonInvalidFormat},
		{"12 -34", false, "", ReasonInvalidFormat},
		{" ", false, "", ReasonInvalidFormat},
		{"12\t34", false, "", ReasonInvalidCharacter},
		{"12.34", false, "", ReasonInvalidCharacter},
		{"12\u00a034", false, "", ReasonInvalidCharacter},
		{"\uff11\uff12", false, "", ReasonInvalidCharacter},
		{"\u0661\u0662", false, "", ReasonInvalidCharacter},
		{"12ab", false, "", ReasonInvalidCharacter},
		{"fr76 ab", true, "FR76AB", ReasonValid},
		{"FR\u00e976", true, "", ReasonInvalidCharacter},
	}
	for _, test := range tests {
		got, reason := compact(test.value, test.letters)
		if got != test.want || reason != test.reason {
			t.Errorf("compact(%q, %v) = %q, %q; want %q, %q", test.value, test.letters, got, reason, test.want, test.reason)
		}
	}
}

func TestLuhn(t *testing.T) {
	for digits, want := range map[string]bool{
		"0": true, "18": true, "79927398713": true, "79927398710": false,
		"4111111111111111": true, "4111111111111112": false, "120027016": true, "123456789": false,
	} {
		if got := luhnValid(digits); got != want {
			t.Errorf("luhnValid(%q) = %v, want %v", digits, got, want)
		}
	}
}

func TestValidatePaymentCard(t *testing.T) {
	runFixtures(t, ValidatePaymentCard, []fixture{
		{"visa 16", "4111111111111111", ReasonValid},
		{"visa grouped spaces", "4111 1111 1111 1111", ReasonValid},
		{"visa grouped hyphens", "4012-8888-8888-1881", ReasonValid},
		{"mastercard", "5555 5555 5555 4444", ReasonValid},
		{"amex 15", "3782 822463 10005", ReasonValid},
		{"diners 14", "30569309025904", ReasonValid},
		{"13 digits", "4222222222222", ReasonValid},
		{"12 digits minimum", "500000000017", ReasonValid},
		{"19 digits maximum", "6221260000000000001", ReasonValid},
		{"luhn mismatch", "4111111111111112", ReasonChecksumMismatch},
		{"single transposition", "4111111111111121", ReasonChecksumMismatch},
		{"all zeros passes luhn but trivial", "0000 0000 0000 0000", ReasonTrivialValue},
		{"repeated digit", "8888888888888888", ReasonTrivialValue},
		{"too short", "50000000001", ReasonTooShort},
		{"too long", "41111111111111111111", ReasonTooLong},
		{"letters", "4111 1111 1111 111A", ReasonInvalidCharacter},
		{"dots", "4111.1111.1111.1111", ReasonInvalidCharacter},
		{"double separator", "4111  1111 1111 1111", ReasonInvalidFormat},
		{"trailing separator", "4111111111111111-", ReasonInvalidFormat},
		{"empty", "", ReasonEmpty},
	})
}

func TestValidateIBAN(t *testing.T) {
	runFixtures(t, ValidateIBAN, []fixture{
		{"france registry example", "FR1420041010050500013M02606", ReasonValid},
		{"france paper format", "FR76 3000 6000 0112 3456 7890 189", ReasonValid},
		{"france lower case", "fr14 2004 1010 0505 0001 3m02 606", ReasonValid},
		{"germany", "DE89 3704 0044 0532 0130 00", ReasonValid},
		{"united kingdom", "GB82WEST12345698765432", ReasonValid},
		{"belgium", "BE68 5390 0754 7034", ReasonValid},
		{"netherlands", "NL91ABNA0417164300", ReasonValid},
		{"norway shortest", "NO93 8601 1117 947", ReasonValid},
		{"saint lucia longest", "LC55HEMM000100010012001200023015", ReasonValid},
		{"malta alphanumeric", "MT84MALT011000012345MTLCAST001S", ReasonValid},
		{"italy letter check char", "IT60X0542811101000000123456", ReasonValid},
		{"kosovo", "XK051212012345678906", ReasonValid},
		{"check digits 02", "BE02539007547058", ReasonValid},
		{"check digits 98", "BE98539007547076", ReasonValid},
		{"checksum mismatch", "DE89370400440532013001", ReasonChecksumMismatch},
		{"transposed digits", "DE89370400440532031000", ReasonChecksumMismatch},
		{"check digits 01 pass mod 97 but are never issued", "BE01539007547076", ReasonInvalidFormat},
		{"check digits 99 pass mod 97 but are never issued", "BE99539007547058", ReasonInvalidFormat},
		{"check digits 00", "BE00539007547076", ReasonInvalidFormat},
		{"letter check digits", "BEA8539007547076", ReasonInvalidFormat},
		{"digits in british bank code", "GB25123412345698765432", ReasonInvalidFormat},
		{"letter in french numeric field", "FR462004A010050500013M02606", ReasonInvalidFormat},
		{"numeric country code", "12345678", ReasonInvalidFormat},
		{"unknown country", "XX1420041010050500013M02606", ReasonUnknownCountry},
		{"united states has no iban", "US64SVBKUS6S3300958879", ReasonUnknownCountry},
		{"too short for france", "FR142004101005050001302606", ReasonTooShort},
		{"too long for france", "FR1420041010050500013M026061", ReasonTooLong},
		{"single letter", "F", ReasonTooShort},
		{"all zero bban", "FR76 0000 0000 0000 0000 0000 000", ReasonTrivialValue},
		{"punctuation", "FR14.2004.1010.0505.0001.3M02.606", ReasonInvalidCharacter},
		{"leading separator", " FR1420041010050500013M02606", ReasonInvalidFormat},
		{"empty", "", ReasonEmpty},
	})
}

func TestIBANRegistry(t *testing.T) {
	if len(ibanFormats) != 89 {
		t.Fatalf("registry has %d countries, want 89 (SWIFT IBAN Registry release 101)", len(ibanFormats))
	}
	for country, want := range map[string]int{
		"FR": 27, "MC": 27, "DE": 22, "GB": 22, "BE": 16, "NL": 18, "IT": 27, "ES": 24,
		"CH": 21, "LU": 20, "PT": 25, "NO": 15, "LC": 32, "RU": 33, "BR": 29, "MU": 30,
	} {
		if got := ibanFormats[country].length; got != want {
			t.Errorf("%s IBAN length = %d, want %d", country, got, want)
		}
	}
	for country := range ibanFormats {
		if len(country) != 2 || !isUpper(country[0]) || !isUpper(country[1]) {
			t.Errorf("invalid country code %q", country)
		}
	}
}

func TestParseBBANStructureRejectsMalformed(t *testing.T) {
	for _, structure := range []string{"", "5n", "5!", "x!n", "0!n", "5!z", "5!n3"} {
		if _, err := parseBBANStructure(structure); err == nil {
			t.Errorf("parseBBANStructure(%q) succeeded, want error", structure)
		}
	}
	if fields, err := parseBBANStructure("5!n5!n11!c2!n"); err != nil || len(fields) != 4 || fields[2] != (bbanField{11, 'c'}) {
		t.Fatalf("parseBBANStructure(FR) = %v, %v", fields, err)
	}
}

func TestMustParseIBANFormatsPanicsOnMalformedEntry(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustParseIBANFormats did not panic")
		}
	}()
	mustParseIBANFormats(map[string]string{"ZZ": "5!q"})
}

func TestValidateNIR(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		reason Reason
		status NIRStatus
	}{
		{"definitive male", "1 85 05 78 006 084 91", ReasonValid, NIRStatusDefinitive},
		{"definitive female compact", "290121900401281", ReasonValid, NIRStatusDefinitive},
		{"hyphen separated", "1-85-05-78-006-084-91", ReasonValid, NIRStatusDefinitive},
		{"corsica 2A reads as 19", "1 85 05 2A 006 084 35", ReasonValid, NIRStatusDefinitive},
		{"corsica 2a lower case", "1 85 05 2a 006 084 35", ReasonValid, NIRStatusDefinitive},
		{"corsica 2B reads as 18", "2 90 12 2B 004 012 11", ReasonValid, NIRStatusDefinitive},
		{"corsica key computed as 20 is wrong", "1 85 05 2A 006 084 08", ReasonChecksumMismatch, NIRStatusNone},
		{"overseas department", "1 85 05 97 409 012 73", ReasonValid, NIRStatusDefinitive},
		{"born abroad provisional 7", "7 80 01 99 123 456 82", ReasonValid, NIRStatusProvisional},
		{"provisional 3", "3 01 01 99 123 045 05", ReasonValid, NIRStatusProvisional},
		{"conventional month 63", "2 75 63 99 216 051 57", ReasonValid, NIRStatusDefinitive},
		{"pseudo-fictitious month 42", "1 85 42 99 001 001 58", ReasonValid, NIRStatusDefinitive},
		{"key mismatch", "1 85 05 78 006 084 92", ReasonChecksumMismatch, NIRStatusNone},
		{"digit typo", "1 85 05 78 006 085 91", ReasonChecksumMismatch, NIRStatusNone},
		{"key 00 never valid", "1 85 05 78 006 084 00", ReasonChecksumMismatch, NIRStatusNone},
		{"sex 5", "5 85 05 78 006 084 91", ReasonInvalidFormat, NIRStatusNone},
		{"sex 0", "0 85 05 78 006 084 91", ReasonInvalidFormat, NIRStatusNone},
		{"month 00", "1 85 00 78 006 084 91", ReasonInvalidFormat, NIRStatusNone},
		{"month 13", "1 85 13 78 006 084 91", ReasonInvalidFormat, NIRStatusNone},
		{"month 45", "1 85 45 78 006 084 91", ReasonInvalidFormat, NIRStatusNone},
		{"department 00", "1 85 05 00 006 084 91", ReasonInvalidFormat, NIRStatusNone},
		{"department 2C", "1 85 05 2C 006 084 35", ReasonInvalidFormat, NIRStatusNone},
		{"letter outside department", "1 85 05 78 0A6 084 91", ReasonInvalidFormat, NIRStatusNone},
		{"letter in key", "1 85 05 78 006 084 9A", ReasonInvalidFormat, NIRStatusNone},
		{"without key", "1 85 05 78 006 084", ReasonTooShort, NIRStatusNone},
		{"too long", "1 85 05 78 006 084 911", ReasonTooLong, NIRStatusNone},
		{"all zeros", "000000000000000", ReasonInvalidFormat, NIRStatusNone},
		{"slash separator", "1/85/05/78/006/084/91", ReasonInvalidCharacter, NIRStatusNone},
		{"empty", "", ReasonEmpty, NIRStatusNone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ValidateNIR(test.value)
			if got.Reason != test.reason || got.Status != test.status || got.Valid != (test.reason == ReasonValid) {
				t.Fatalf("ValidateNIR = %+v, want reason %q status %q", got, test.reason, test.status)
			}
		})
	}
}

func TestValidateSIREN(t *testing.T) {
	runFixtures(t, ValidateSIREN, []fixture{
		{"insee own siren", "120027016", ReasonValid},
		{"grouped", "120 027 016", ReasonValid},
		{"la poste", "356 000 000", ReasonValid},
		{"synthetic", "732829320", ReasonValid},
		{"insee counter-example", "123456789", ReasonChecksumMismatch},
		{"all zeros passes luhn but trivial", "000000000", ReasonTrivialValue},
		{"too short", "12002701", ReasonTooShort},
		{"too long", "1200270160", ReasonTooLong},
		{"letter", "12002701A", ReasonInvalidCharacter},
		{"empty", "", ReasonEmpty},
	})
}

func TestValidateSIRET(t *testing.T) {
	runFixtures(t, ValidateSIRET, []fixture{
		{"synthetic", "12002701600035", ReasonValid},
		{"grouped", "120 027 016 00035", ReasonValid},
		{"synthetic other", "732 829 320 00017", ReasonValid},
		{"luhn mismatch", "12002701600036", ReasonChecksumMismatch},
		{"invalid siren with luhn-valid siret", "12345678900007", ReasonChecksumMismatch},
		{"la poste head office uses luhn", "356 000 000 00048", ReasonValid},
		{"la poste establishment uses digit sum", "356 000 000 49639", ReasonValid},
		{"la poste digit sum multiple of 5", "35600000012346", ReasonValid},
		{"la poste establishment passing luhn only", "35600000012340", ReasonChecksumMismatch},
		{"la poste digit sum not multiple of 5", "35600000049630", ReasonChecksumMismatch},
		{"all zeros", "00000000000000", ReasonTrivialValue},
		{"too short", "1200270160003", ReasonTooShort},
		{"too long", "120027016000351", ReasonTooLong},
		{"empty", "", ReasonEmpty},
	})
}

func TestValidateDispatch(t *testing.T) {
	values := map[Kind]string{
		KindPaymentCard: "4111111111111111",
		KindIBAN:        "FR1420041010050500013M02606",
		KindFRNIR:       "185057800608491",
		KindFRSIREN:     "120027016",
		KindFRSIRET:     "12002701600035",
	}
	for _, kind := range Kinds() {
		if got := Validate(kind, values[kind]); !got.Valid {
			t.Errorf("Validate(%s) = %+v, want valid", kind, got)
		}
		if got := Validate(kind, "x"); got.Valid {
			t.Errorf("Validate(%s, x) = %+v, want invalid", kind, got)
		}
	}
	if got := Validate(Kind("unknown"), "4111111111111111"); got != (Result{Reason: ReasonInvalidFormat}) {
		t.Errorf("Validate(unknown) = %+v", got)
	}
}

func TestParseKind(t *testing.T) {
	for _, kind := range Kinds() {
		got, err := ParseKind(kind.String())
		if err != nil || got != kind {
			t.Errorf("ParseKind(%q) = %q, %v", kind, got, err)
		}
	}
	if _, err := ParseKind("Payment_Card"); err == nil || !strings.Contains(err.Error(), "unknown validator kind") {
		t.Errorf("ParseKind(Payment_Card) error = %v", err)
	}
}

func TestStringers(t *testing.T) {
	if ReasonChecksumMismatch.String() != "checksum_mismatch" || NIRStatusProvisional.String() != "provisional" {
		t.Fatal("unexpected string conversion")
	}
}
