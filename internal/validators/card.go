package validators

const (
	// paymentCardMinDigits is the shortest primary account number length in
	// use by major card schemes (12-digit Maestro numbers).
	paymentCardMinDigits = 12
	// paymentCardMaxDigits is the ISO/IEC 7812-1 maximum PAN length.
	paymentCardMaxDigits = 19
)

// ValidatePaymentCard validates a payment card primary account number: 12 to
// 19 digits whose Luhn check passes. Values made of a single repeated digit
// (for example sixteen zeros, which pass Luhn) are ReasonTrivialValue. Issuer
// identification number ranges are not checked, so test numbers published by
// card schemes are valid.
func ValidatePaymentCard(value string) Result {
	digits, reason := digitsOnly(value, paymentCardMinDigits, paymentCardMaxDigits)
	switch {
	case reason != ReasonValid:
		return invalid(reason)
	case allSame(digits):
		return invalid(ReasonTrivialValue)
	case !luhnValid(digits):
		return invalid(ReasonChecksumMismatch)
	}
	return valid()
}
