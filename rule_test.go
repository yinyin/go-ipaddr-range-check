package ipaddrrangecheck_test

import (
	"net"
	"testing"

	ipaddrrangecheck "github.com/yinyin/go-ipaddr-range-check"
)

func TestRuleSetContains1(t *testing.T) {
	var ruleSet ipaddrrangecheck.RuleSet
	ruleSet.AppendEqualAddress(net.ParseIP("192.0.2.1"))
	ruleSet.AppendEqualAddress(net.ParseIP("2001:db8::68"))
	_, ipNet1, err := net.ParseCIDR("192.168.3.0/24")
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}
	ruleSet.AppendWithinNetwork(ipNet1)
	_, ipNet2, err := net.ParseCIDR("2001:db8:a0b:12f0::1/32")
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}
	ruleSet.AppendWithinNetwork(ipNet2)
	ruleSet.AppendWithinRange(net.ParseIP("192.168.5.10"), net.ParseIP("192.168.5.16"))
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
