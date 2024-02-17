package ipaddrrangecheck

import (
	"errors"
)

var ErrInvalidRule = errors.New("invalid check rule")

var ErrInsufficientBinaryBuffer = errors.New("insufficient binary buffer")

var ErrPackedBinarySizeMismatch = errors.New("packed binary size mismatch")

var ErrPackedBinaryBroken = errors.New("packed binary broken")

var ErrPackedBinaryUnsupportedVersion = errors.New("packed binary unsupported version")

var ErrInvalidRuleType = errors.New("invalid rule type")
