package ipaddrrangecheck

type RuleType int

const (
	UnknownRule RuleType = iota
	EqualAddress
	WithinNetwork
	WithinRange
)
