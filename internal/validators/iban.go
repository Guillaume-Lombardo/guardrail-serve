package validators

import (
	"fmt"
	"strconv"
	"strings"
)

// bbanField is one "<length>!<type>" element of a registry BBAN structure.
type bbanField struct {
	length int
	class  byte // 'n' digits, 'a' upper-case letters, 'c' upper-case alphanumerics
}

type ibanFormat struct {
	length int // full IBAN length
	fields []bbanField
}

var ibanFormats = mustParseIBANFormats(ibanBBANStructures)

func mustParseIBANFormats(structures map[string]string) map[string]ibanFormat {
	formats := make(map[string]ibanFormat, len(structures))
	for country, structure := range structures {
		fields, err := parseBBANStructure(structure)
		if err != nil {
			panic(fmt.Sprintf("validators: IBAN registry entry %s: %v", country, err))
		}
		format := ibanFormat{length: 4, fields: fields}
		for _, field := range fields {
			format.length += field.length
		}
		formats[country] = format
	}
	return formats
}

func parseBBANStructure(structure string) ([]bbanField, error) {
	var fields []bbanField
	for rest := structure; rest != ""; {
		lengthText, after, ok := strings.Cut(rest, "!")
		if !ok || after == "" {
			return nil, fmt.Errorf("malformed structure %q", structure)
		}
		length, err := strconv.Atoi(lengthText)
		if err != nil || length <= 0 {
			return nil, fmt.Errorf("malformed length in %q", structure)
		}
		class := after[0]
		if class != 'n' && class != 'a' && class != 'c' {
			return nil, fmt.Errorf("unknown character class %q in %q", class, structure)
		}
		fields = append(fields, bbanField{length: length, class: class})
		rest = after[1:]
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty structure")
	}
	return fields, nil
}

// ValidateIBAN validates an International Bank Account Number (ISO 13616-1)
// in electronic or paper format:
//
//   - the country code must be listed in the SWIFT IBAN Registry and the length
//     must match that country's registered length;
//   - the check digits must be 02 to 98 and the BBAN must match the registered
//     structure of digits, letters, and alphanumerics;
//   - the ISO 7064 MOD 97-10 check must yield 1;
//   - a BBAN made of a single repeated character is ReasonTrivialValue.
//
// Letters are accepted in either case. National BBAN check digits (for
// example the French RIB key) are not verified.
func ValidateIBAN(value string) Result {
	iban, reason := compact(value, true)
	if reason != ReasonValid {
		return invalid(reason)
	}
	if len(iban) < 2 {
		return invalid(ReasonTooShort)
	}
	if !isUpper(iban[0]) || !isUpper(iban[1]) {
		return invalid(ReasonInvalidFormat)
	}
	format, known := ibanFormats[iban[:2]]
	switch {
	case !known:
		return invalid(ReasonUnknownCountry)
	case len(iban) < format.length:
		return invalid(ReasonTooShort)
	case len(iban) > format.length:
		return invalid(ReasonTooLong)
	}
	if !isDigit(iban[2]) || !isDigit(iban[3]) {
		return invalid(ReasonInvalidFormat)
	}
	if check := iban[2:4]; check < "02" || check > "98" {
		return invalid(ReasonInvalidFormat)
	}
	bban := iban[4:]
	offset := 0
	for _, field := range format.fields {
		for _, char := range []byte(bban[offset : offset+field.length]) {
			if !field.accepts(char) {
				return invalid(ReasonInvalidFormat)
			}
		}
		offset += field.length
	}
	if allSame(bban) {
		return invalid(ReasonTrivialValue)
	}
	if ibanMod97(bban+iban[:4]) != 1 {
		return invalid(ReasonChecksumMismatch)
	}
	return valid()
}

func (f bbanField) accepts(char byte) bool {
	switch f.class {
	case 'n':
		return isDigit(char)
	case 'a':
		return isUpper(char)
	}
	return isDigit(char) || isUpper(char)
}

// ibanMod97 computes the ISO 7064 MOD 97-10 remainder of an upper-case
// alphanumeric string, letters counting as 10 (A) to 35 (Z).
func ibanMod97(rearranged string) int {
	remainder := 0
	for index := range len(rearranged) {
		char := rearranged[index]
		if isDigit(char) {
			remainder = (remainder*10 + int(char-'0')) % 97
			continue
		}
		remainder = (remainder*100 + int(char-'A') + 10) % 97
	}
	return remainder
}

func isDigit(char byte) bool { return char >= '0' && char <= '9' }

func isUpper(char byte) bool { return char >= 'A' && char <= 'Z' }
