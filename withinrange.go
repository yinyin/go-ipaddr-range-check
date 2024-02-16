package ipaddrrangecheck

import (
	"bytes"
	"net"
)

type WithinRangeRule struct {
	FromIP  net.IP
	UntilIP net.IP
}

func NewWithinRangeRule(fromIP net.IP, untilIP net.IP) *WithinRangeRule {
	if len(fromIP) != len(untilIP) {
		fromIP = fromIP.To16()
		untilIP = untilIP.To16()
	}
	return &WithinRangeRule{
		FromIP:  fromIP,
		UntilIP: untilIP,
	}
}

func (rule *WithinRangeRule) Contains(ip net.IP) bool {
	sizeIP := len(ip)
	if sizeIP == 0 {
		return false
	}
	sizeFrom := len(rule.FromIP)
	sizeUntil := len(rule.UntilIP)
	if (sizeIP != sizeFrom) || (sizeIP != sizeUntil) || (sizeFrom != sizeUntil) {
		ip16 := ip.To16()
		from16 := rule.FromIP.To16()
		untl16 := rule.UntilIP.To16()
		return bytes.Compare(ip16, from16) >= 0 && bytes.Compare(ip16, untl16) <= 0
	}
	return bytes.Compare(ip, rule.FromIP) >= 0 && bytes.Compare(ip, rule.UntilIP) <= 0
}
