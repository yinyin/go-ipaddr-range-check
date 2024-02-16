package ipaddrrangecheck_test

import (
	"net"
	"testing"

	ipaddrrangecheck "github.com/yinyin/go-ipaddr-range-check"
)

func TestWithinRangeRule1(t *testing.T) {
	rule := ipaddrrangecheck.NewWithinRangeRule(
		net.ParseIP("192.168.0.10"),
		net.ParseIP("192.168.0.20"))
	if !rule.Contains(net.ParseIP("192.168.0.10")) {
		t.Error("unexpected result: false")
	}
	if !rule.Contains(net.ParseIP("192.168.0.15")) {
		t.Error("unexpected result: false")
	}
	if !rule.Contains(net.ParseIP("192.168.0.20")) {
		t.Error("unexpected result: false")
	}
	if rule.Contains(net.ParseIP("192.168.0.33")) {
		t.Error("unexpected result: true")
	}
	if rule.Contains(net.ParseIP("127.0.0.1")) {
		t.Error("unexpected result: true")
	}
}

func TestWithinRangeRule2(t *testing.T) {
	rule := ipaddrrangecheck.NewWithinRangeRule(
		nil,
		net.ParseIP("192.168.0.20"))
	if rule == nil {
		t.Error("unexpected result: nil")
	}
	if rule.Contains(nil) {
		t.Error("unexpected result: true")
	}
	if !rule.Contains(net.ParseIP("192.16.0.0")) {
		t.Error("unexpected result: false")
	}
	if !rule.Contains(net.ParseIP("192.168.0.20")) {
		t.Error("unexpected result: false")
	}
	if rule.Contains(net.ParseIP("192.168.0.21")) {
		t.Error("unexpected result: true")
	}
}
