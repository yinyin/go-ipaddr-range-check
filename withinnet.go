package ipaddrrangecheck

import (
	"net"
)

type WithinNetworkRule net.IPNet

func (rule *WithinNetworkRule) Contains(ip net.IP) bool {
	return (*net.IPNet)(rule).Contains(ip)
}
