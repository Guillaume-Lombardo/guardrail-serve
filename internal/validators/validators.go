// Package validators provides pure, deterministic format and checksum
// validators for identifiers that guardrails detect: payment card numbers
// (Luhn), IBANs (ISO 13616, MOD 97-10), French NIR social security numbers,
// and French SIREN/SIRET business identifiers.
//
// Validators never log, store, or return the validated value. Inputs follow
// the separator rule documented on Validate; see README.md in this directory
// for the rules and their primary sources.
package validators

import "fmt"

// Kind names a validator.
type Kind string

const (
	KindPaymentCard Kind = "payment_card"
	KindIBAN        Kind = "iban"
	KindFRNIR       Kind = "fr_nir"
	KindFRSIREN     Kind = "fr_siren"
	KindFRSIRET     Kind = "fr_siret"
)

// Kinds lists every validator kind in a stable order.
func Kinds() []Kind {
	return []Kind{KindPaymentCard, KindIBAN, KindFRNIR, KindFRSIREN, KindFRSIRET}
}

// ParseKind converts a configuration string into a Kind.
func ParseKind(value string) (Kind, error) {
	for _, kind := range Kinds() {
		if string(kind) == value {
			return kind, nil
		}
	}
	return "", fmt.Errorf("unknown validator kind %q (expected payment_card, iban, fr_nir, fr_siren or fr_siret)", value)
}

func (k Kind) String() string { return string(k) }

// Reason explains a validation outcome. It never contains the value.
type Reason string

const (
	ReasonValid            Reason = "valid"
	ReasonEmpty            Reason = "empty"
	ReasonInvalidCharacter Reason = "invalid_character"
	ReasonInvalidFormat    Reason = "invalid_format"
	ReasonTooShort         Reason = "too_short"
	ReasonTooLong          Reason = "too_long"
	ReasonUnknownCountry   Reason = "unknown_country"
	ReasonChecksumMismatch Reason = "checksum_mismatch"
	ReasonTrivialValue     Reason = "trivial_value"
)

func (r Reason) String() string { return string(r) }

// Result is a validation outcome. Valid is true exactly when Reason is
// ReasonValid.
type Result struct {
	Valid  bool
	Reason Reason
}

func valid() Result { return Result{Valid: true, Reason: ReasonValid} }

func invalid(reason Reason) Result { return Result{Reason: reason} }

// Validate runs the validator named by kind. An unknown kind is reported as
// ReasonInvalidFormat; use ParseKind to reject unknown kinds at configuration
// time.
//
// Separator rule, shared by every validator: the value may contain ASCII
// space (U+0020) and hyphen-minus (U+002D) as group separators. A separator
// must sit between two significant characters, so leading, trailing, and
// consecutive separators are ReasonInvalidFormat. Grouping is free: the
// validators do not require the conventional group sizes. Any other character
// (tabs, dots, no-break spaces, non-ASCII digits, ...) is
// ReasonInvalidCharacter; callers that accept such forms normalize first, for
// example with internal/textnorm. ASCII letters are accepted case-insensitively
// where the identifier contains letters (IBAN, Corsican NIR) and are
// ReasonInvalidCharacter elsewhere.
func Validate(kind Kind, value string) Result {
	switch kind {
	case KindPaymentCard:
		return ValidatePaymentCard(value)
	case KindIBAN:
		return ValidateIBAN(value)
	case KindFRNIR:
		return ValidateNIR(value).Result
	case KindFRSIREN:
		return ValidateSIREN(value)
	case KindFRSIRET:
		return ValidateSIRET(value)
	}
	return invalid(ReasonInvalidFormat)
}

// compact applies the separator rule and returns the significant characters,
// with ASCII letters upper-cased when letters are allowed.
func compact(value string, letters bool) (string, Reason) {
	if value == "" {
		return "", ReasonEmpty
	}
	out := make([]byte, 0, len(value))
	afterSeparator := true // a value cannot start with a separator
	for _, r := range value {
		switch {
		case r == ' ' || r == '-':
			if afterSeparator {
				return "", ReasonInvalidFormat
			}
			afterSeparator = true
			continue
		case r >= '0' && r <= '9':
		case letters && r >= 'A' && r <= 'Z':
		case letters && r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		default:
			return "", ReasonInvalidCharacter
		}
		afterSeparator = false
		out = append(out, byte(r))
	}
	if afterSeparator {
		return "", ReasonInvalidFormat
	}
	return string(out), ReasonValid
}

// digitsOnly applies the separator rule and requires between minLength and
// maxLength ASCII digits.
func digitsOnly(value string, minLength, maxLength int) (string, Reason) {
	digits, reason := compact(value, false)
	if reason != ReasonValid {
		return "", reason
	}
	switch {
	case len(digits) < minLength:
		return "", ReasonTooShort
	case len(digits) > maxLength:
		return "", ReasonTooLong
	}
	return digits, ReasonValid
}

// allSame reports whether every byte of s is identical.
func allSame(s string) bool {
	for index := 1; index < len(s); index++ {
		if s[index] != s[0] {
			return false
		}
	}
	return true
}

// luhnValid reports whether the decimal string passes the Luhn (mod 10)
// check, the doubled positions being every second digit from the right.
func luhnValid(digits string) bool {
	sum := 0
	for index := len(digits) - 1; index >= 0; index-- {
		digit := int(digits[index] - '0')
		if (len(digits)-1-index)%2 == 1 {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}
