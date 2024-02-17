package ipaddrrangecheck

import (
	"bytes"
)

type RuleType int

const (
	UnknownRule RuleType = iota
	EqualAddress
	WithinNetwork
	WithinRange
)

const (
	equalAddressIdentText  = "same_address"
	withinNetworkIdentText = "in_network"
	withinRangeIdentText   = "in_range"
)

var (
	equalAddressIdentBytes  = []byte(equalAddressIdentText)
	withinNetworkIdentBytes = []byte(withinNetworkIdentText)
	withinRangeIdentBytes   = []byte(withinRangeIdentText)
)

func (t RuleType) MarshalText() (text []byte, err error) {
	switch t {
	case EqualAddress:
		return equalAddressIdentBytes, nil
	case WithinNetwork:
		return withinNetworkIdentBytes, nil
	case WithinRange:
		return withinRangeIdentBytes, nil
	}
	return nil, ErrInvalidRuleType
}

func (ref *RuleType) UnmarshalText(text []byte) error {
	switch {
	case bytes.Equal(text, equalAddressIdentBytes):
		*ref = EqualAddress
	case bytes.Equal(text, withinNetworkIdentBytes):
		*ref = WithinNetwork
	case bytes.Equal(text, withinRangeIdentBytes):
		*ref = WithinRange
	default:
		return ErrInvalidRuleType
	}
	return nil
}
