package validators

// ibanBBANStructures maps each ISO 3166-1 alpha-2 country code to its BBAN
// structure, as published in the SWIFT IBAN Registry release 101. The notation
// is the registry's: "<length>!<type>" where n is a digit, a an upper-case
// letter, and c an upper-case letter or digit; every IBAN is the country code,
// two check digits, then the BBAN, so its length is 4 plus the BBAN length.
var ibanBBANStructures = map[string]string{
	"AD": "4!n4!n12!c",          // Andorra, IBAN length 24
	"AE": "3!n16!n",             // United Arab Emirates (The), IBAN length 23
	"AL": "8!n16!c",             // Albania, IBAN length 28
	"AT": "5!n11!n",             // Austria, IBAN length 20
	"AZ": "4!a20!c",             // Azerbaijan, IBAN length 28
	"BA": "3!n3!n8!n2!n",        // Bosnia and Herzegovina, IBAN length 20
	"BE": "3!n7!n2!n",           // Belgium, IBAN length 16
	"BG": "4!a4!n2!n8!c",        // Bulgaria, IBAN length 22
	"BH": "4!a14!c",             // Bahrain, IBAN length 22
	"BI": "5!n5!n11!n2!n",       // Burundi, IBAN length 27
	"BR": "8!n5!n10!n1!a1!c",    // Brazil, IBAN length 29
	"BY": "4!c4!n16!c",          // Belarus, IBAN length 28
	"CH": "5!n12!c",             // Switzerland, IBAN length 21
	"CR": "4!n14!n",             // Costa Rica, IBAN length 22
	"CY": "3!n5!n16!c",          // Cyprus, IBAN length 28
	"CZ": "4!n16!n",             // Czechia, IBAN length 24
	"DE": "8!n10!n",             // Germany, IBAN length 22
	"DJ": "5!n5!n11!n2!n",       // Djibouti, IBAN length 27
	"DK": "4!n9!n1!n",           // Denmark, IBAN length 18
	"DO": "4!c20!n",             // Dominican Republic, IBAN length 28
	"EE": "2!n14!n",             // Estonia, IBAN length 20
	"EG": "4!n4!n17!n",          // Egypt, IBAN length 29
	"ES": "4!n4!n1!n1!n10!n",    // Spain, IBAN length 24
	"FI": "3!n11!n",             // Finland, IBAN length 18
	"FK": "2!a12!n",             // Falkland Islands (Malvinas), IBAN length 18
	"FO": "4!n9!n1!n",           // Faroe Islands, IBAN length 18
	"FR": "5!n5!n11!c2!n",       // France, IBAN length 27
	"GB": "4!a6!n8!n",           // United Kingdom, IBAN length 22
	"GE": "2!a16!n",             // Georgia, IBAN length 22
	"GI": "4!a15!c",             // Gibraltar, IBAN length 23
	"GL": "4!n9!n1!n",           // Greenland, IBAN length 18
	"GR": "3!n4!n16!c",          // Greece, IBAN length 27
	"GT": "4!c20!c",             // Guatemala, IBAN length 28
	"HN": "4!a20!n",             // Honduras, IBAN length 28
	"HR": "7!n10!n",             // Croatia, IBAN length 21
	"HU": "3!n4!n1!n15!n1!n",    // Hungary, IBAN length 28
	"IE": "4!a6!n8!n",           // Ireland, IBAN length 22
	"IL": "3!n3!n13!n",          // Israel, IBAN length 23
	"IQ": "4!a3!n12!n",          // Iraq, IBAN length 23
	"IS": "4!n2!n6!n10!n",       // Iceland, IBAN length 26
	"IT": "1!a5!n5!n12!c",       // Italy, IBAN length 27
	"JO": "4!a4!n18!c",          // Jordan, IBAN length 30
	"KW": "4!a22!c",             // Kuwait, IBAN length 30
	"KZ": "3!n13!c",             // Kazakhstan, IBAN length 20
	"LB": "4!n20!c",             // Lebanon, IBAN length 28
	"LC": "4!a24!c",             // Saint Lucia, IBAN length 32
	"LI": "5!n12!c",             // Liechtenstein, IBAN length 21
	"LT": "5!n11!n",             // Lithuania, IBAN length 20
	"LU": "3!n13!c",             // Luxembourg, IBAN length 20
	"LV": "4!a13!c",             // Latvia, IBAN length 21
	"LY": "3!n3!n15!n",          // Libya, IBAN length 25
	"MC": "5!n5!n11!c2!n",       // Monaco, IBAN length 27
	"MD": "2!c18!c",             // Moldova, Republic of, IBAN length 24
	"ME": "3!n13!n2!n",          // Montenegro, IBAN length 22
	"MK": "3!n10!c2!n",          // North Macedonia, IBAN length 19
	"MN": "4!n12!n",             // Mongolia, IBAN length 20
	"MR": "5!n5!n11!n2!n",       // Mauritania, IBAN length 27
	"MT": "4!a5!n18!c",          // Malta, IBAN length 31
	"MU": "4!a2!n2!n12!n3!n3!a", // Mauritius, IBAN length 30
	"NI": "4!a20!n",             // Nicaragua, IBAN length 28
	"NL": "4!a10!n",             // Netherlands (The), IBAN length 18
	"NO": "4!n6!n1!n",           // Norway, IBAN length 15
	"OM": "3!n16!c",             // Oman, IBAN length 23
	"PK": "4!a16!c",             // Pakistan, IBAN length 24
	"PL": "8!n16!n",             // Poland, IBAN length 28
	"PS": "4!a21!c",             // Palestine, State of, IBAN length 29
	"PT": "4!n4!n11!n2!n",       // Portugal, IBAN length 25
	"QA": "4!a21!c",             // Qatar, IBAN length 29
	"RO": "4!a16!c",             // Romania, IBAN length 24
	"RS": "3!n13!n2!n",          // Serbia, IBAN length 22
	"RU": "9!n5!n15!c",          // Russian Federation, IBAN length 33
	"SA": "2!n18!c",             // Saudi Arabia, IBAN length 24
	"SC": "4!a2!n2!n16!n3!a",    // Seychelles, IBAN length 31
	"SD": "2!n12!n",             // Sudan, IBAN length 18
	"SE": "3!n16!n1!n",          // Sweden, IBAN length 24
	"SI": "5!n8!n2!n",           // Slovenia, IBAN length 19
	"SK": "4!n6!n10!n",          // Slovakia, IBAN length 24
	"SM": "1!a5!n5!n12!c",       // San Marino, IBAN length 27
	"SO": "4!n3!n12!n",          // Somalia, IBAN length 23
	"ST": "4!n4!n11!n2!n",       // Sao Tome and Principe, IBAN length 25
	"SV": "4!a20!n",             // El Salvador, IBAN length 28
	"TL": "3!n14!n2!n",          // Timor-Leste, IBAN length 23
	"TN": "2!n3!n13!n2!n",       // Tunisia, IBAN length 24
	"TR": "5!n1!n16!c",          // Turkiye, IBAN length 26
	"UA": "6!n19!c",             // Ukraine, IBAN length 29
	"VA": "3!n15!n",             // Holy See, IBAN length 22
	"VG": "4!a16!n",             // Virgin Islands (British), IBAN length 24
	"XK": "4!n10!n2!n",          // Kosovo, IBAN length 20
	"YE": "4!a4!n18!c",          // Yemen, IBAN length 30
}
