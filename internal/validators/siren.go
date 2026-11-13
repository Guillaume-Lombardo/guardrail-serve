package validators

const (
	sirenDigits = 9
	siretDigits = 14

	// laPosteSIREN groups every La Poste establishment. INSEE (Sirene user
	// letter no. 16, November 2013): except for the head office, a La Poste
	// SIRET is valid when the plain sum of its 14 digits is a multiple of 5.
	laPosteSIREN = "356000000"
	// laPosteHeadOfficeSIRET follows the regular Luhn rule.
	laPosteHeadOfficeSIRET = "35600000000048"
)

// ValidateSIREN validates a French SIREN business identifier: 9 digits whose
// Luhn check passes (INSEE). A single repeated digit, such as 000000000, is
// ReasonTrivialValue.
func ValidateSIREN(value string) Result {
	digits, reason := digitsOnly(value, sirenDigits, sirenDigits)
	if reason != ReasonValid {
		return invalid(reason)
	}
	return checkSIREN(digits)
}

func checkSIREN(digits string) Result {
	switch {
	case allSame(digits):
		return invalid(ReasonTrivialValue)
	case !luhnValid(digits):
		return invalid(ReasonChecksumMismatch)
	}
	return valid()
}

// ValidateSIRET validates a French SIRET establishment identifier: a valid
// SIREN followed by a 5-digit NIC, the 14 digits passing the Luhn check
// (INSEE). La Poste establishments (SIREN 356000000) other than the head
// office use the INSEE exception instead: the sum of the 14 digits must be a
// multiple of 5. A single repeated digit is ReasonTrivialValue.
func ValidateSIRET(value string) Result {
	digits, reason := digitsOnly(value, siretDigits, siretDigits)
	if reason != ReasonValid {
		return invalid(reason)
	}
	if allSame(digits) {
		return invalid(ReasonTrivialValue)
	}
	if result := checkSIREN(digits[:sirenDigits]); !result.Valid {
		return result
	}
	if digits[:sirenDigits] == laPosteSIREN && digits != laPosteHeadOfficeSIRET {
		sum := 0
		for index := range len(digits) {
			sum += int(digits[index] - '0')
		}
		if sum%5 != 0 {
			return invalid(ReasonChecksumMismatch)
		}
		return valid()
	}
	if !luhnValid(digits) {
		return invalid(ReasonChecksumMismatch)
	}
	return valid()
}
