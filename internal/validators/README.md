# validators

Pure, deterministic validators for identifiers that guardrails detect. No I/O,
no logging, no dependency outside the standard library; results never contain
the validated value.

```go
validators.ValidateIBAN("FR76 3000 6000 0112 3456 7890 189")    // {Valid: true, Reason: "valid"}
validators.ValidateNIR("1 85 05 2A 006 084 35").Status           // "definitive"
validators.Validate(validators.KindPaymentCard, "4111111111111112") // {Valid: false, Reason: "checksum_mismatch"}
```

| Kind | Function | Rule |
|---|---|---|
| `payment_card` | `ValidatePaymentCard` | 12-19 digits, Luhn |
| `iban` | `ValidateIBAN` | SWIFT registry country, length and BBAN structure, check digits 02-98, ISO 7064 MOD 97-10 |
| `fr_nir` | `ValidateNIR` | 15 characters, structure, key = 97 - (13 digits mod 97), 2A/2B Corsica |
| `fr_siren` | `ValidateSIREN` | 9 digits, Luhn |
| `fr_siret` | `ValidateSIRET` | 14 digits, valid SIREN, Luhn; La Poste exception |

`ParseKind` converts configuration strings; `Kinds` lists them.

## Reasons

`valid`, `empty`, `invalid_character`, `invalid_format`, `too_short`,
`too_long`, `unknown_country` (IBAN), `checksum_mismatch`, `trivial_value`.
Checks run in this order: separators and characters, length, structure,
trivial value, checksum.

## Input format

ASCII space and hyphen-minus are the only group separators. A separator must
sit between two significant characters: leading, trailing, or doubled
separators are `invalid_format`. Group sizes are not enforced, so
`4111 1111 1111 1111`, `4111-1111-1111-1111`, and `4111111111111111` are all
accepted. Any other character, including tabs, dots, no-break spaces, and
fullwidth or non-Latin digits, is `invalid_character`: normalize first (for
example with `internal/textnorm`, whose NFKC maps fullwidth digits and
no-break spaces to ASCII). Letters are accepted in either case where the
identifier contains letters (IBAN, Corsican NIR department).

## Rules and sources

### Payment cards

Luhn (mod 10) over 12 to 19 digits. 19 is the ISO/IEC 7812-1 maximum PAN
length; 12 is the shortest length issued by major schemes (Maestro). Issuer
ranges are not checked. A single repeated digit (for example sixteen zeros,
which pass Luhn) is `trivial_value`.

### IBAN

- Country codes, lengths, and BBAN structures (`n` digits, `a` upper-case
  letters, `c` upper-case alphanumerics) come from the SWIFT IBAN Registry
  release 101 (89 countries), in `iban_registry.go`. French overseas
  departments and collectivities use the `FR` entry.
- ISO 13616-1: check digits are 02 to 98; 00, 01, and 99 can satisfy MOD 97
  but are never issued, so they are `invalid_format`.
- ISO 7064 MOD 97-10: move the first four characters to the end, replace
  letters with 10 (A) to 35 (Z), and the number modulo 97 must be 1.
- A BBAN made of one repeated character is `trivial_value`.
- National check digits inside the BBAN (French RIB key, ...) are not checked.

### French NIR

Sources: L'Assurance retraite / net-entreprises, "Veillez à la bonne
identification de vos salariés" (NIR composition, months above 12 when the
month is unknown, 2A/2B, 97/98 overseas, numbers starting with 7 or 8 issued
provisionally); MSA, "Votre numéro de sécurité sociale" (numbers starting
with 3, 4, 7, or 8 are provisional); circular DSS/SD4C/2012/213 of 1 June 2012
(the NIA waiting number has the same technical structure as the NIR); the
government key calculator at cle-nir.inclusion.gouv.fr (2A read as 19, 2B as
18, key = 97 - number mod 97).

| Positions | Accepted |
|---|---|
| 1 | `1`, `2` (status `definitive`); `3`, `4`, `7`, `8` (status `provisional`) |
| 2-3 | any two digits (year) |
| 4-5 | `01`-`12`, `20`-`42`, `50`-`99` (codes used when the civil status record lacks or only partially gives the month, including conventional codes such as 62 and 63) |
| 6-7 | `01`-`99` or `2A`/`2B`; `00` rejected |
| 8-13 | any digits (commune or country code and order number) |
| 14-15 | key, 01-97 |

Provisional numbers are valid (`Valid: true`) because they still identify a
person; `NIRResult.Status` lets callers treat them differently. Months 13-19
and 43-49 are rejected because no source documents them; the key alone would
already reject almost all random values. The key is required: 13 characters
are `too_short`. Commune and order values are not checked, since their ranges
depend on the department and on historical codes.

### SIREN and SIRET

Source: INSEE, Sirene user letter no. 16 (November 2013), "Vérifier la
validité d'un siren": Luhn over the 9 SIREN digits and over the 14 SIRET
digits (INSEE's own SIREN 120027016 is the worked example). For La Poste
establishments (SIREN 356000000), except the head office
(SIRET 356 000 000 00048, which follows Luhn), the plain sum of the 14 digits
must be a multiple of 5. A SIRET must also start with a valid SIREN. A single
repeated digit (000000000 passes Luhn) is `trivial_value`.
