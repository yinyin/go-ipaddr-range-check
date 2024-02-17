package ipaddrrangecheck

import (
	"encoding/json"
	"net"
)

type EqualAddressRule net.IP

func (rule EqualAddressRule) Contains(ip net.IP) bool {
	return ip.Equal(net.IP(rule))
}

type equalAddressRulePacked struct {
	EqualTo string `json:"equal_to"`
}

func (rule EqualAddressRule) MarshalJSON() ([]byte, error) {
	return json.Marshal(&equalAddressRulePacked{
		EqualTo: net.IP(rule).String(),
	})
}

func (ruleRef *EqualAddressRule) UnmarshalJSON(buf []byte) (err error) {
	var packed equalAddressRulePacked
	if err = json.Unmarshal(buf, &packed); nil != err {
		return
	}
	ip := net.ParseIP(packed.EqualTo)
	if ip == nil {
		return ErrInvalidRule
	}
	*ruleRef = EqualAddressRule(ip)
	return
}

func (rule EqualAddressRule) binaryPackedLen() int {
	return 1 + len(rule)
}

func (rule EqualAddressRule) packBinaryInto(buf []byte) {
	byteCount := len(rule)
	buf[0] = byte(byteCount)
	if byteCount == 0 {
		return
	}
	copy(buf[1:], ([]byte)(rule))
}

func newEqualAddressRuleFromPackedBinary(buf []byte) (n int, rule EqualAddressRule) {
	byteCount := int(buf[0])
	n = 1 + byteCount
	if byteCount == 0 {
		return
	}
	ipValue := make([]byte, byteCount)
	copy(ipValue, buf[1:])
	rule = EqualAddressRule(ipValue)
	return
}
