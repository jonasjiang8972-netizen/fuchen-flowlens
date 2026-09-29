package sensitive

import (
	"testing"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

func TestValidIDCard(t *testing.T) {
	// 11010519491231002X is the standard sample with a valid check digit.
	if !ValidIDCard("11010519491231002X") {
		t.Fatal("valid ID rejected")
	}
	if ValidIDCard("110105194912310021") {
		t.Fatal("bad check digit accepted")
	}
}

func TestScanUnmaskedAndMasked(t *testing.T) {
	body := `{"id_card":"11010519491231002X","phone":"13812345678","card":"4111 1111 1111 1111",` +
		`"email":"alice@example.com","p2":"138****5678","c2":"622202******1234","i2":"110***********002X"}`
	f := ScanText(body)
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"unmasked id", f.Unmasked[IDCard], 1},
		{"unmasked phone", f.Unmasked[Phone], 1},
		{"unmasked card", f.Unmasked[BankCard], 1},
		{"email", f.Unmasked[Email], 1},
		{"masked phone", f.Masked[Phone], 1},
		{"masked card", f.Masked[BankCard], 1},
		{"masked id", f.Masked[IDCard], 1},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d (%+v)", tc.name, tc.got, tc.want, f)
		}
	}
	if f.UnmaskedTotal() != 3 {
		t.Errorf("UnmaskedTotal = %d, want 3 (email is not held to masking)", f.UnmaskedTotal())
	}
}

func TestScanIgnoresLookalikes(t *testing.T) {
	// Fails the ID check digit, fails Luhn, 13-digit timestamp, repeated digits.
	f := ScanText(`{"a":"110105194912310021","b":"1234567890123456","ts":1767225600000,"c":"0000000000000000"}`)
	if !f.Empty() {
		t.Fatalf("lookalikes matched: %+v", f)
	}
}

func TestIDNotCountedAsCard(t *testing.T) {
	// 18-digit IDs can pass Luhn; they must count once, as ID cards.
	f := ScanText("11010519491231002X")
	if f.Unmasked[IDCard] != 1 || f.Unmasked[BankCard] != 0 {
		t.Fatalf("%+v", f)
	}
}

func TestAnnotateOnce(t *testing.T) {
	evt := &shared.APIEvent{Content: shared.ContentLayer{ResponseBody: []byte(`{"p":"13812345678"}`)}}
	Annotate(evt)
	if got := FromLabels(evt).Unmasked[Phone]; got != 1 {
		t.Fatalf("unmasked phone = %d, want 1", got)
	}
	// The body is masked afterwards; a second pass must not erase the finding.
	evt.Content.ResponseBody = []byte(`{"p":"138****5678"}`)
	Annotate(evt)
	f := FromLabels(evt)
	if f.Unmasked[Phone] != 1 || f.Masked[Phone] != 0 {
		t.Fatalf("second pass changed findings: %+v", f)
	}
}
