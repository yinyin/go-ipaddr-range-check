package ipaddrrangecheck_test

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"

	ipaddrrangecheck "github.com/yinyin/go-ipaddr-range-check"
)

func makeTestRuleSetD01(t *testing.T) (ruleSet ipaddrrangecheck.RuleSet, err error) {
	ruleSet.AppendEqualAddress(net.ParseIP("192.0.2.1"))
	ruleSet.AppendEqualAddress(net.ParseIP("2001:db8::68"))
	_, ipNet1, err := net.ParseCIDR("192.168.3.0/24")
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
		return
	}
	ruleSet.AppendWithinNetwork(ipNet1)
	_, ipNet2, err := net.ParseCIDR("2001:db8:a0b:12f0::1/32")
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
		return
	}
	ruleSet.AppendWithinNetwork(ipNet2)
	ruleSet.AppendWithinRange(net.ParseIP("192.168.5.10"), net.ParseIP("192.168.5.16"))
	return
}

func TestRuleSetContains1(t *testing.T) {
	ruleSet, _ := makeTestRuleSetD01(t)
	if !ruleSet.Contains(net.ParseIP("192.0.2.1")) {
		t.Error("expected result: false")
	}
	if !ruleSet.Contains(net.ParseIP("2001:db8::68")) {
		t.Error("expected result: false")
	}
	if !ruleSet.Contains(net.ParseIP("192.168.3.1")) {
		t.Error("expected result: false")
	}
	if !ruleSet.Contains(net.ParseIP("192.168.5.16")) {
		t.Error("expected result: false")
	}
	if ruleSet.Contains(net.ParseIP("127.0.0.1")) {
		t.Error("expected result: true")
	}
}

func TestRuleSetBinaryPack1(t *testing.T) {
	ruleSet0, _ := makeTestRuleSetD01(t)
	packed, err := ruleSet0.MarshalBinary()
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("binary data: size=%d", len(packed))
	var ruleSet1 ipaddrrangecheck.RuleSet
	if err = ruleSet1.UnmarshalBinary(packed); nil != err {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff(ruleSet0.RuleEntries(), ruleSet1.RuleEntries()); diff != "" {
		t.Errorf("unexpected result (-want +got):\n%s", diff)
	}
}

func TestRuleSetJSONTranscode1(t *testing.T) {
	ruleSet0, _ := makeTestRuleSetD01(t)
	buf, err := json.MarshalIndent(&ruleSet0, "", "  ")
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("JSON data: content=%s", string(buf))
	var ruleSet1 ipaddrrangecheck.RuleSet
	if err = json.Unmarshal(buf, &ruleSet1); nil != err {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := cmp.Diff(ruleSet0.RuleEntries(), ruleSet1.RuleEntries()); diff != "" {
		t.Errorf("unexpected result (-want +got):\n%s", diff)
	}
}
