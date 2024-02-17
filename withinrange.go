package ipaddrrangecheck

import (
	"bytes"
	"encoding/json"
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

type withinRangeRulePacked struct {
	FromAddr  string `json:"from_address"`
	UntilAddr string `json:"until_address"`
}

func (rule *WithinRangeRule) MarshalJSON() ([]byte, error) {
	return json.Marshal(&withinRangeRulePacked{
		FromAddr:  rule.FromIP.String(),
		UntilAddr: rule.UntilIP.String(),
	})
}

func (rule *WithinRangeRule) UnmarshalJSON(buf []byte) (err error) {
	var packed withinRangeRulePacked
	if err = json.Unmarshal(buf, &packed); nil != err {
		return
	}
	fromIP := net.ParseIP(packed.FromAddr)
	untilIP := net.ParseIP(packed.UntilAddr)
	if (fromIP == nil) || (untilIP == nil) {
		return ErrInvalidRule
	}
	*rule = WithinRangeRule{
		FromIP:  fromIP,
		UntilIP: untilIP,
	}
	return
}

func (rule *WithinRangeRule) binaryPackedLen() int {
	return 2 + len(rule.FromIP) + len(rule.UntilIP)
}

func (rule *WithinRangeRule) packBinaryInto(buf []byte) {
	byteCountFromIP := len(rule.FromIP)
	byteCountUntilIP := len(rule.UntilIP)
	buf[0] = byte(byteCountFromIP)
	buf[1] = byte(byteCountUntilIP)
	if byteCountFromIP != 0 {
		copy(buf[2:], ([]byte)(rule.FromIP))
	}
	if byteCountUntilIP != 0 {
		copy(buf[2+byteCountFromIP:], ([]byte)(rule.UntilIP))
	}
}

func newWithinRangeRuleFromPackedBinary(buf []byte) (n int, rule *WithinRangeRule) {
	byteCountFromIP := int(buf[0])
	byteCountUntilIP := int(buf[1])
	n = 2 + byteCountFromIP + byteCountUntilIP
	var fromIPValue, untilIPValue []byte
	if byteCountFromIP != 0 {
		fromIPValue = make([]byte, byteCountFromIP)
		copy(fromIPValue, buf[2:])
	}
	if byteCountUntilIP != 0 {
		untilIPValue = make([]byte, byteCountUntilIP)
		copy(untilIPValue, buf[2+byteCountFromIP:])
	}
	rule = &WithinRangeRule{
		FromIP:  fromIPValue,
		UntilIP: untilIPValue,
	}
	return
}
