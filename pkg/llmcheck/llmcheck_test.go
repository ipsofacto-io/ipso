package llmcheck

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAndValidateRequiresFixturesWhenBlocking(t *testing.T) {
	noDeny := []byte(`{
		"version": 1,
		"target": "json-snapshot",
		"rubric": "Production firewall policies must deny default 0.0.0.0/0 egress.",
		"fixtures": [
			{"id": "deny-all", "expect": "allow", "input": "{\"egress\": \"deny\"}"}
		]
	}`)
	if _, err := ParseAndValidate(noDeny, "json-snapshot", false); err != nil {
		t.Fatalf("warn/advise mode rejected valid spec: %v", err)
	}
	_, err := ParseAndValidate(noDeny, "json-snapshot", true)
	var coded *Error
	if !errors.As(err, &coded) || coded.Code != CodeFixturesRequired {
		t.Fatalf("err = %v, want code %s", err, CodeFixturesRequired)
	}

	complete := []byte(`{
		"version": 1,
		"target": "json-snapshot",
		"rubric": "Production firewall policies must deny default 0.0.0.0/0 egress.",
		"fixtures": [
			{"id": "deny-all", "expect": "allow", "input": "{\"default_egress\": \"deny\"}"},
			{"id": "open-internet", "expect": "deny", "input": "{\"default_egress\": \"0.0.0.0/0 allow\"}"}
		]
	}`)
	spec, err := ParseAndValidate(complete, "json-snapshot", true)
	if err != nil {
		t.Fatalf("ParseAndValidate complete: %v", err)
	}
	raw, err := MarshalCanonical(spec)
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	if !strings.Contains(string(raw), `"open-internet"`) {
		t.Fatalf("canonical output missing fixture: %s", raw)
	}
}

func TestVerifyAnswerEnforcesVerbatimQuote(t *testing.T) {
	input := `{"rule": "egress-default", "cidr": "0.0.0.0/0", "action": "allow"}`
	okAns, err := VerifyAnswer(input, []byte(`{"verdict":"fail","findings":[{"quote":"\"cidr\": \"0.0.0.0/0\", \"action\": \"allow\"","message":"Default internet egress is allowed."}]}`))
	if err != nil {
		t.Fatalf("VerifyAnswer valid quote: %v", err)
	}
	if okAns.Verdict != "fail" || len(okAns.Findings) != 1 {
		t.Fatalf("ans = %+v", okAns)
	}

	_, err = VerifyAnswer(input, []byte(`{"verdict":"fail","findings":[{"quote":"0.0.0.0/0 -> allow","message":"Paraphrased quote."}]}`))
	var coded *Error
	if !errors.As(err, &coded) || coded.Code != CodeUngroundedQuote {
		t.Fatalf("err = %v, want %s", err, CodeUngroundedQuote)
	}

	_, err = VerifyAnswer(input, []byte(`{"verdict":"fail","findings":[]}`))
	if !errors.As(err, &coded) || coded.Code != CodeInvalidAnswer {
		t.Fatalf("err = %v, want %s", err, CodeInvalidAnswer)
	}
}

func TestRedactStripsSecretsAndEmails(t *testing.T) {
	raw := "owner=alice@example.com\nAuthorization: Bearer ipsocli_1234567890abcdefghij\napi_key = \"supersecretvalue123\"\n-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----"
	got := Redact(raw)
	for _, secret := range []string{"alice@example.com", "ipsocli_1234567890abcdefghij", "supersecretvalue123", "BEGIN EC PRIVATE KEY"} {
		if strings.Contains(got, secret) {
			t.Fatalf("Redact leaked %q in %q", secret, got)
		}
	}
}
