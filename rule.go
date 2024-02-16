package ipaddrrangecheck

import (
	"net"
)

type Rule interface {
	Contains(ip net.IP) bool
}

type RuleEntry struct {
	RuleType     RuleType
	RuleInstance Rule
}

type RuleSet struct {
	rules []RuleEntry
}

func (ruleSet *RuleSet) Contains(ip net.IP) bool {
	for _, rule := range ruleSet.rules {
		if rule.RuleInstance.Contains(ip) {
			return true
		}
	}
	return false
}

func (ruleSet *RuleSet) AppendEqualAddress(targetIP net.IP) {
	ruleSet.rules = append(ruleSet.rules, RuleEntry{
		RuleType:     EqualAddress,
		RuleInstance: EqualAddressRule(targetIP),
	})
}

func (ruleSet *RuleSet) AppendWithinNetwork(targetNetwork *net.IPNet) {
	ruleSet.rules = append(ruleSet.rules, RuleEntry{
		RuleType:     WithinNetwork,
		RuleInstance: (*WithinNetworkRule)(targetNetwork),
	})
}

func (ruleSet *RuleSet) AppendWithinRange(fromIP net.IP, untilIP net.IP) {
	ruleSet.rules = append(ruleSet.rules, RuleEntry{
		RuleType:     WithinRange,
		RuleInstance: NewWithinRangeRule(fromIP, untilIP),
	})
}
