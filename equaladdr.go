package ipaddrrangecheck

import (
	"net"
)

type EqualAddressRule net.IP

func (rule EqualAddressRule) Contains(ip net.IP) bool {
	return ip.Equal(net.IP(rule))
}
