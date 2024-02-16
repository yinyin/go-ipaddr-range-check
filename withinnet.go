package ipaddrrangecheck

import (
	"net"
)

type WithinNetworkRule net.IPNet

func NewWithinNetworkRuleViaCIDR(s string) (*WithinNetworkRule, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return (*WithinNetworkRule)(ipNet), nil
}

func (rule *WithinNetworkRule) Contains(ip net.IP) bool {
	return (*net.IPNet)(rule).Contains(ip)
}
