package validate

import (
	"fmt"
	"regexp"
)

// This is copied from golang-lru
const dns1123LabelFmt string = "[a-z0-9]([-a-z0-9]*[a-z0-9])?"
const dns1123LabelErrMsg string = "a lowercase RFC 1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an alphanumeric character"

// DNS1123LabelMaxLength is a label's max length in DNS (RFC 1123)
const DNS1123LabelMaxLength int = 63

var dns1123LabelRegexp = regexp.MustCompile("^" + dns1123LabelFmt + "$")

// MaxLenError returns a string explanation of a "string too long" validation
// failure.
func MaxLenError(length int) string {
	return fmt.Sprintf("must be no more than %d characters", length)
}

// RegexError returns a string explanation of a regex validation failure.
func RegexError(msg string, fmt string, examples ...string) string {
	if len(examples) == 0 {
		return msg + " (regex used for validation is '" + fmt + "')"
	}
	msg += " (e.g. "
	for i := range examples {
		if i > 0 {
			msg += " or "
		}
		msg += "'" + examples[i] + "', "
	}
	msg += "regex used for validation is '" + fmt + "')"
	return msg
}

func IsValidName(value string) []string {
	var errs []string
	if len(value) > DNS1123LabelMaxLength {
		errs = append(errs, MaxLenError(DNS1123LabelMaxLength))
	}
	if !dns1123LabelRegexp.MatchString(value) {
		errs = append(errs, RegexError(dns1123LabelErrMsg, dns1123LabelFmt, "my-name", "123-abc"))
	}
	return errs
}
