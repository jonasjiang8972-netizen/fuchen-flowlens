// Package sensitive finds personal financial data (ID card, mobile number,
// bank card, e-mail) in API responses and tells masked values from unmasked
// ones. Only counts are kept, never the values themselves.
//
// The collector scans before it redacts, so the result survives redaction and
// reaches the platform as event labels (dlp.unmasked.<type>, dlp.masked.<type>).
package sensitive

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

// Type is a class of sensitive data.
type Type string

const (
	IDCard   Type = "id_card"
	Phone    Type = "phone"
	BankCard Type = "bank_card"
	Email    Type = "email"
)

// Types lists every detected class in display order.
var Types = []Type{IDCard, Phone, BankCard, Email}

// Name returns the Chinese display name of a type.
func (t Type) Name() string {
	switch t {
	case IDCard:
		return "身份证号"
	case Phone:
		return "手机号"
	case BankCard:
		return "银行卡号"
	case Email:
		return "邮箱"
	}
	return string(t)
}

// Maskable reports whether the platform expects values of the type to be
// masked in responses. E-mail is detected but not held to a masking rule.
func (t Type) Maskable() bool { return t != Email }

const (
	labelUnmasked = "dlp.unmasked."
	labelMasked   = "dlp.masked."
	labelScanned  = "dlp.scanned"
	maxScanBytes  = 256 << 10
)

// Findings counts sensitive values in one message.
type Findings struct {
	Unmasked map[Type]int
	Masked   map[Type]int
}

func newFindings() Findings {
	return Findings{Unmasked: map[Type]int{}, Masked: map[Type]int{}}
}

// Total is the number of sensitive values found, masked or not.
func (f Findings) Total() int { return f.UnmaskedTotal() + f.MaskedTotal() }

// UnmaskedTotal counts values that should have been masked but were not.
// E-mail is excluded, see Type.Maskable.
func (f Findings) UnmaskedTotal() int {
	n := 0
	for t, c := range f.Unmasked {
		if t.Maskable() {
			n += c
		}
	}
	return n
}

// MaskedTotal counts values already masked.
func (f Findings) MaskedTotal() int {
	n := 0
	for _, c := range f.Masked {
		n += c
	}
	return n
}

// Empty reports whether nothing was found.
func (f Findings) Empty() bool {
	return f.Total() == 0 && len(f.Unmasked)+len(f.Masked) == 0
}

var (
	idCardRe = regexp.MustCompile(`\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`)
	phoneRe  = regexp.MustCompile(`\b1[3-9]\d{9}\b`)
	cardRe   = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
	emailRe  = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)

	// Masked forms as produced by pkg/redact and common application masking.
	maskedIDRe    = regexp.MustCompile(`\b\d{3,6}\*{8,}[\dXx]{4}\b`)
	maskedPhoneRe = regexp.MustCompile(`\b1[3-9]\d\*{3,}\d{4}\b`)
	maskedCardRe  = regexp.MustCompile(`\b\d{4,6}[ -]?\*{3,}(?:[ -]?\*+)*[ -]?\d{3,4}\b`)
	maskedEmailRe = regexp.MustCompile(`\b[A-Za-z0-9._%+-]{1,3}\*+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
)

// Scan counts sensitive values in the response body of evt.
func Scan(evt *shared.APIEvent) Findings {
	body := evt.Content.ResponseBody
	if len(body) > maxScanBytes {
		body = body[:maxScanBytes]
	}
	return ScanText(string(body))
}

// ScanText counts sensitive values in text. A digit run is counted once,
// as the first type that accepts it: ID card, then bank card, then phone.
func ScanText(s string) Findings {
	f := newFindings()
	if s == "" {
		return f
	}

	// Masked forms first, and remove them so the unmasked patterns cannot
	// match around the mask characters.
	s = countAndBlank(s, maskedIDRe, f.Masked, IDCard)
	s = countAndBlank(s, maskedEmailRe, f.Masked, Email)
	s = countAndBlank(s, maskedCardRe, f.Masked, BankCard)
	s = countAndBlank(s, maskedPhoneRe, f.Masked, Phone)

	s = replaceMatching(s, idCardRe, func(v string) bool { return ValidIDCard(v) }, f.Unmasked, IDCard)
	s = replaceMatching(s, cardRe, func(v string) bool {
		d := strings.NewReplacer(" ", "", "-", "").Replace(v)
		return len(d) >= 13 && len(d) <= 19 && !allSame(d) && Luhn(d)
	}, f.Unmasked, BankCard)
	s = replaceMatching(s, phoneRe, func(string) bool { return true }, f.Unmasked, Phone)
	countAndBlank(s, emailRe, f.Unmasked, Email)

	for _, m := range []map[Type]int{f.Unmasked, f.Masked} {
		for t, c := range m {
			if c == 0 {
				delete(m, t)
			}
		}
	}
	return f
}

func countAndBlank(s string, re *regexp.Regexp, into map[Type]int, t Type) string {
	return re.ReplaceAllStringFunc(s, func(string) string {
		into[t]++
		return " "
	})
}

func replaceMatching(s string, re *regexp.Regexp, valid func(string) bool, into map[Type]int, t Type) string {
	return re.ReplaceAllStringFunc(s, func(v string) string {
		if !valid(v) {
			return v
		}
		into[t]++
		return " "
	})
}

// ValidIDCard checks the GB 11643 check digit of an 18-digit resident ID.
func ValidIDCard(id string) bool {
	if len(id) != 18 {
		return false
	}
	weights := [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	const check = "10X98765432"
	sum := 0
	for i := 0; i < 17; i++ {
		d, err := strconv.Atoi(id[i : i+1])
		if err != nil {
			return false
		}
		sum += d * weights[i]
	}
	return check[sum%11] == byte(strings.ToUpper(id[17:])[0])
}

// Luhn reports whether a digit string passes the Luhn check.
func Luhn(digits string) bool {
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func allSame(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// Annotate scans evt and records the counts as labels. It runs once per
// event: a collector's result is kept, because the platform's own scan of an
// already-redacted body would find nothing and could only lose information.
func Annotate(evt *shared.APIEvent) {
	if evt.Metadata.Labels[labelScanned] != "" {
		return
	}
	f := Scan(evt)
	if evt.Metadata.Labels == nil {
		evt.Metadata.Labels = map[string]string{}
	}
	evt.Metadata.Labels[labelScanned] = "1"
	for t, c := range f.Unmasked {
		evt.Metadata.Labels[labelUnmasked+string(t)] = strconv.Itoa(c)
	}
	for t, c := range f.Masked {
		evt.Metadata.Labels[labelMasked+string(t)] = strconv.Itoa(c)
	}
}

// FromLabels reads the findings a collector attached to the event.
func FromLabels(evt *shared.APIEvent) Findings {
	f := newFindings()
	for _, t := range Types {
		if n, err := strconv.Atoi(evt.Metadata.Labels[labelUnmasked+string(t)]); err == nil && n > 0 {
			f.Unmasked[t] = n
		}
		if n, err := strconv.Atoi(evt.Metadata.Labels[labelMasked+string(t)]); err == nil && n > 0 {
			f.Masked[t] = n
		}
	}
	return f
}
