package ipaddrrangecheck_test

import (
	"net"
	"testing"

	ipaddrrangecheck "github.com/yinyin/go-ipaddr-range-check"
)

func TestWithinNetwork1(t *testing.T) {
	rule, err := ipaddrrangecheck.NewWithinNetworkRuleViaCIDR("192.0.2.1/24")
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rule.Contains(net.ParseIP("192.0.2.1")) {
		t.Error("unexpected result: false")
	}
	if !rule.Contains(net.ParseIP("192.0.2.30")) {
		t.Error("unexpected result: false")
	}
	if !rule.Contains(net.ParseIP("192.0.2.255")) {
		t.Error("unexpected result: false")
	}
	if rule.Contains(net.ParseIP("127.0.0.1")) {
		t.Error("unexpected result: true")
	}
	if rule.Contains(net.ParseIP("2001:db8:a0b:12f0::1")) {
		t.Error("unexpected result: true")
	}
}

func TestWithinNetwork2(t *testing.T) {
	rule, err := ipaddrrangecheck.NewWithinNetworkRuleViaCIDR("2001:db8:a0b:12f0::1/32")
	if nil != err {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rule.Contains(net.ParseIP("2001:db8:a0b:12f0::1")) {
		t.Error("unexpected result: false")
	}
	if !rule.Contains(net.ParseIP("2001:db8:a0b:39::8")) {
		t.Error("unexpected result: false")
	}
	if rule.Contains(net.ParseIP("192.0.2.1")) {
		t.Error("unexpected result: true")
	}
	if rule.Contains(net.ParseIP("127.0.0.1")) {
		t.Error("unexpected result: true")
	}
}
