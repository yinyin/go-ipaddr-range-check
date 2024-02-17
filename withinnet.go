package ipaddrrangecheck

import (
	"encoding/json"
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

type withinNetworkRulePacked struct {
	InNetwork string `json:"in_network"`
}

func (rule *WithinNetworkRule) MarshalJSON() ([]byte, error) {
	return json.Marshal(&withinNetworkRulePacked{
		InNetwork: (*net.IPNet)(rule).String(),
	})
}

func (rule *WithinNetworkRule) UnmarshalJSON(buf []byte) (err error) {
	var packed withinNetworkRulePacked
	if err = json.Unmarshal(buf, &packed); nil != err {
		return
	}
	if packed.InNetwork == "" {
		err = ErrInvalidRule
		return
	}
	_, ipNet, err := net.ParseCIDR(packed.InNetwork)
	if nil != err {
		return
	}
	*rule = (WithinNetworkRule)(*ipNet)
	return
}

func (rule *WithinNetworkRule) binaryPackedLen() int {
	origRef := (*net.IPNet)(rule)
	return 2 + len(origRef.IP) + len(origRef.Mask)
}

func (rule *WithinNetworkRule) packBinaryInto(buf []byte) {
	origRef := (*net.IPNet)(rule)
	byteCountIP := len(origRef.IP)
	byteCountMask := len(origRef.Mask)
	buf[0] = byte(byteCountIP)
	buf[1] = byte(byteCountMask)
	if byteCountIP != 0 {
		copy(buf[2:], ([]byte)(origRef.IP))
	}
	if byteCountMask != 0 {
		copy(buf[2+byteCountIP:], ([]byte)(origRef.Mask))
	}
}

func newWithinNetworkRuleFromPackedBinary(buf []byte) (n int, rule *WithinNetworkRule) {
	byteCountIP := int(buf[0])
	byteCountMask := int(buf[1])
	n = 2 + byteCountIP + byteCountMask
	var ipValue, maskValue []byte
	if byteCountIP != 0 {
		ipValue = make([]byte, byteCountIP)
		copy(ipValue, buf[2:])
	}
	if byteCountMask != 0 {
		maskValue = make([]byte, byteCountMask)
		copy(maskValue, buf[2+byteCountIP:])
	}
	ipNet := net.IPNet{
		IP:   ipValue,
		Mask: maskValue,
	}
	rule = (*WithinNetworkRule)(&ipNet)
	return
}
