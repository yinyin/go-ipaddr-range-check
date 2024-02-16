package ipaddrrangecheck_test

import (
	"net"
	"testing"

	ipaddrrangecheck "github.com/yinyin/go-ipaddr-range-check"
)

func TestEqualAddressRule1(t *testing.T) {
	rule := ipaddrrangecheck.EqualAddressRule(net.ParseIP("192.0.2.1"))
	if !rule.Contains(net.ParseIP("192.0.2.1")) {
		t.Error("unexpected result: false")
	}
	if !rule.Contains(net.ParseIP("::ffff:192.0.2.1")) {
		t.Error("unexpected result: false")
	}
	if rule.Contains(net.ParseIP("127.0.0.1")) {
		t.Error("unexpected result: true")
	}
}

func TestEqualAddressRule2(t *testing.T) {
	rule := ipaddrrangecheck.EqualAddressRule(net.ParseIP("::ffff:192.0.2.1"))
	if !rule.Contains(net.ParseIP("192.0.2.1")) {
		t.Error("unexpected result: false")
	}
	if !rule.Contains(net.ParseIP("::ffff:192.0.2.1")) {
		t.Error("unexpected result: false")
	}
	if rule.Contains(net.ParseIP("127.0.0.1")) {
		t.Error("unexpected result: true")
	}
}

func TestEqualAddressRule3(t *testing.T) {
	rule := ipaddrrangecheck.EqualAddressRule(net.ParseIP("2001:db8::68"))
	if !rule.Contains(net.ParseIP("2001:db8::68")) {
		t.Error("unexpected result: false")
	}
	if rule.Contains(net.ParseIP("::ffff:192.0.2.1")) {
		t.Error("unexpected result: true")
	}
	if rule.Contains(net.ParseIP("127.0.0.1")) {
		t.Error("unexpected result: true")
	}
}
