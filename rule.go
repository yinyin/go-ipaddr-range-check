package ipaddrrangecheck

import (
	"encoding/binary"
	"encoding/json"
	"hash/adler32"
	"net"
)

const BinaryPackageVersion1 = 1

type Rule interface {
	Contains(ip net.IP) bool

	binaryPackedLen() int
	packBinaryInto(buf []byte)
}

type RuleEntry struct {
	RuleType     RuleType `json:"rule_type"`
	RuleInstance Rule     `json:"condition"`
}

func (entry *RuleEntry) UnmarshalJSON(buf []byte) (err error) {
	var packed struct {
		RuleType RuleType `json:"rule_type"`
	}
	if err = json.Unmarshal(buf, &packed); nil != err {
		return
	}
	var ruleInstance Rule
	entry.RuleType = packed.RuleType
	switch packed.RuleType {
	case EqualAddress:
		var entryImpl struct {
			RuleInstance EqualAddressRule `json:"condition"`
		}
		if err = json.Unmarshal(buf, &entryImpl); nil != err {
			return
		}
		ruleInstance = entryImpl.RuleInstance
	case WithinNetwork:
		var entryImpl struct {
			RuleInstance WithinNetworkRule `json:"condition"`
		}
		if err = json.Unmarshal(buf, &entryImpl); nil != err {
			return
		}
		ruleInstance = &entryImpl.RuleInstance
	case WithinRange:
		var entryImpl struct {
			RuleInstance WithinRangeRule `json:"condition"`
		}
		if err = json.Unmarshal(buf, &entryImpl); nil != err {
			return
		}
		ruleInstance = &entryImpl.RuleInstance
	default:
		return ErrInvalidRuleType
	}
	*entry = RuleEntry{
		RuleType:     packed.RuleType,
		RuleInstance: ruleInstance,
	}
	return

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

// RuleEntries returns the internal slice of rule entries in the RuleSet.
// Do not alter the content of returned slice as it will also modify the content
// of rules in the ruleSet.
func (ruleSet *RuleSet) RuleEntries() []RuleEntry {
	return ruleSet.rules
}

type ruleSetPacked struct {
	Rules []RuleEntry `json:"rules"`
}

func (ruleSet *RuleSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(&ruleSetPacked{
		Rules: ruleSet.rules,
	})
}

func (ruleSet *RuleSet) UnmarshalJSON(buf []byte) (err error) {
	var packed ruleSetPacked
	if err = json.Unmarshal(buf, &packed); nil != err {
		return
	}
	*ruleSet = RuleSet{
		rules: packed.Rules,
	}
	return
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

// MarshalBinary returns the binary representation of the RuleSet.
// The binary representation is:
// - 4 bytes for Adler-32 checksum of the rest of binary package.
// - 4 bytes for total size (include checksum) of binary package.
// - 4 byte for count of rules.
// - 1 byte for binary package version.
// - rules in the following repeated format:
// --- 1 byte for rule type (RuleType), value 0 (UnknownRule) stop rule packs.
// --- packed rule binary.
func (ruleSet *RuleSet) MarshalBinary() (data []byte, err error) {
	offsetWithChecksum := 4 + 4 + 4 + 1
	ruleCount := len(ruleSet.rules)
	expectOffsets := make([]int, ruleCount)
	for idx, rule := range ruleSet.rules {
		expectOffsets[idx] = offsetWithChecksum
		offsetWithChecksum += (1 + rule.RuleInstance.binaryPackedLen())
	}
	sizeWithChecksum := offsetWithChecksum + 1
	data = make([]byte, sizeWithChecksum)
	binary.LittleEndian.PutUint32(data[4:], uint32(sizeWithChecksum))
	binary.LittleEndian.PutUint32(data[8:], uint32(ruleCount))
	data[12] = BinaryPackageVersion1
	for idx, rule := range ruleSet.rules {
		offsetBytes := expectOffsets[idx]
		data[offsetBytes] = byte(rule.RuleType)
		rule.RuleInstance.packBinaryInto(data[offsetBytes+1:])
	}
	checksum := adler32.Checksum(data[4:])
	binary.LittleEndian.PutUint32(data, checksum)
	return
}

func (ruleSet *RuleSet) UnmarshalBinary(data []byte) error {
	if len(data) < (4 + 4 + 4 + 1 + 1) {
		return ErrInsufficientBinaryBuffer
	}
	sizeWithChecksum := int(binary.LittleEndian.Uint32(data[4:]))
	if sizeWithChecksum != len(data) {
		return ErrPackedBinarySizeMismatch
	}
	checksum := binary.LittleEndian.Uint32(data)
	if checksum != adler32.Checksum(data[4:]) {
		return ErrPackedBinaryBroken
	}
	ruleCount := int(binary.LittleEndian.Uint32(data[8:]))
	if ruleCount < 0 {
		return ErrPackedBinaryBroken
	}
	if data[12] != BinaryPackageVersion1 {
		return ErrPackedBinaryUnsupportedVersion
	}
	rules := make([]RuleEntry, 0, ruleCount)
	offsetWithChecksum := 4 + 4 + 4 + 1
	for idx := 0; idx < ruleCount; idx++ {
		ruleType := RuleType(data[offsetWithChecksum])
		if ruleType == UnknownRule {
			break
		}
		var ruleInstance Rule
		switch ruleType {
		case EqualAddress:
			n, ruleImpl := newEqualAddressRuleFromPackedBinary(data[offsetWithChecksum+1:])
			offsetWithChecksum += (1 + n)
			ruleInstance = ruleImpl
		case WithinNetwork:
			n, ruleImpl := newWithinNetworkRuleFromPackedBinary(data[offsetWithChecksum+1:])
			ruleInstance = ruleImpl
			offsetWithChecksum += (1 + n)
		case WithinRange:
			n, ruleImpl := newWithinRangeRuleFromPackedBinary(data[offsetWithChecksum+1:])
			offsetWithChecksum += (1 + n)
			ruleInstance = ruleImpl
		default:
			return ErrInvalidRuleType
		}
		rules = append(rules, RuleEntry{
			RuleType:     ruleType,
			RuleInstance: ruleInstance,
		})
	}
	*ruleSet = RuleSet{
		rules: rules,
	}
	return nil
}
