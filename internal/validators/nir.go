package validators

const nirLength = 15 // 13 identifier characters and a 2-digit key

// NIRStatus qualifies a valid NIR.
type NIRStatus string

const (
	// NIRStatusNone is the status of an invalid NIR.
	NIRStatusNone NIRStatus = ""
	// NIRStatusDefinitive is a NIR whose first digit is 1 or 2.
	NIRStatusDefinitive NIRStatus = "definitive"
	// NIRStatusProvisional is a temporary number with the NIR structure whose
	// first digit is 3, 4, 7, or 8 (assigned pending registration, for
	// example a NIA). It is still personal data.
	NIRStatusProvisional NIRStatus = "provisional"
)

func (s NIRStatus) String() string { return string(s) }

// NIRResult is the outcome of ValidateNIR.
type NIRResult struct {
	Result
	Status NIRStatus
}

// ValidateNIR validates a French NIR (numéro d'inscription au répertoire,
// the social security number) with its key, 15 characters in total:
//
//   - position 1: 1 or 2 (definitive), or 3, 4, 7, 8 (provisional);
//   - positions 2-3: year of birth, any two digits;
//   - positions 4-5: month 01-12, or 20-42 and 50-99 used when the civil
//     status record lacks or only partially gives the month;
//   - positions 6-7: department 01-99, or 2A/2B for Corsica (either case);
//     00 is rejected;
//   - positions 8-13: commune or country code and order number, any digits;
//   - positions 14-15: key, equal to 97 minus the remainder of the first 13
//     digits divided by 97, with 2A read as 19 and 2B as 18.
//
// Spaces and hyphens follow the shared separator rule (see Validate).
func ValidateNIR(value string) NIRResult {
	nir, reason := compact(value, true)
	if reason != ReasonValid {
		return NIRResult{Result: invalid(reason)}
	}
	switch {
	case len(nir) < nirLength:
		return NIRResult{Result: invalid(ReasonTooShort)}
	case len(nir) > nirLength:
		return NIRResult{Result: invalid(ReasonTooLong)}
	}

	// Letters are only allowed as the Corsican department 2A or 2B.
	department := nir[5:7]
	numeric := nir[:13]
	switch department {
	case "2A":
		numeric = nir[:5] + "19" + nir[7:13]
	case "2B":
		numeric = nir[:5] + "18" + nir[7:13]
	}
	for index := range len(numeric) {
		if !isDigit(numeric[index]) {
			return NIRResult{Result: invalid(ReasonInvalidFormat)}
		}
	}
	key := nir[13:]
	if !isDigit(key[0]) || !isDigit(key[1]) {
		return NIRResult{Result: invalid(ReasonInvalidFormat)}
	}

	var status NIRStatus
	switch nir[0] {
	case '1', '2':
		status = NIRStatusDefinitive
	case '3', '4', '7', '8':
		status = NIRStatusProvisional
	default:
		return NIRResult{Result: invalid(ReasonInvalidFormat)}
	}
	month := twoDigits(nir[3:5])
	if !(month >= 1 && month <= 12 || month >= 20 && month <= 42 || month >= 50) {
		return NIRResult{Result: invalid(ReasonInvalidFormat)}
	}
	if department == "00" {
		return NIRResult{Result: invalid(ReasonInvalidFormat)}
	}

	var number uint64
	for index := range len(numeric) {
		number = number*10 + uint64(numeric[index]-'0')
	}
	if want := 97 - int(number%97); twoDigits(key) != want {
		return NIRResult{Result: invalid(ReasonChecksumMismatch)}
	}
	return NIRResult{Result: valid(), Status: status}
}

func twoDigits(s string) int { return int(s[0]-'0')*10 + int(s[1]-'0') }
