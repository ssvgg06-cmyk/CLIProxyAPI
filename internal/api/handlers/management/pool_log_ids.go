package management

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
)

const (
	cpaUpstreamRequestIDDomain = "cpa-upstream-v1\x00"
	cpaUpstreamRequestIDPrefix = "req_01"
	cpaRequestIDBase62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	cpaRequestIDBase62Width    = 22
)

// cpaRequestID returns the real upstream identifier observed by New API. When
// the source did not provide one, the canonical New API request identifier is
// the stable fallback. Neither source identifier is modified or replaced.
func (e poolLogEntry) cpaRequestID() string {
	if e.UpstreamID != "" {
		return e.UpstreamID
	}
	return e.RequestID
}

// cpaUpstreamRequestID projects the canonical New API request identifier into
// the Anthropic-shaped identifier displayed by CPA. The domain separator keeps
// this presentation identifier independent from every other request mapping.
func (e poolLogEntry) cpaUpstreamRequestID() string {
	return projectCPAUpstreamRequestID(e.RequestID)
}

func projectCPAUpstreamRequestID(canonicalRequestID string) string {
	if canonicalRequestID == "" {
		return ""
	}
	digest := sha256.Sum256(append([]byte(cpaUpstreamRequestIDDomain), []byte(canonicalRequestID)...))
	return cpaUpstreamRequestIDPrefix + encodeCPARequestIDBase62(digest[:16])
}

// encodeCPARequestIDBase62 encodes an unsigned 128-bit big-endian value as a
// fixed-width Base62 string. Twenty-two Base62 digits cover the full 128-bit
// range; smaller values are left-padded with the zero digit.
func encodeCPARequestIDBase62(value []byte) string {
	var fixed [16]byte
	if len(value) > len(fixed) {
		value = value[len(value)-len(fixed):]
	}
	copy(fixed[len(fixed)-len(value):], value)
	high := binary.BigEndian.Uint64(fixed[:8])
	low := binary.BigEndian.Uint64(fixed[8:])
	encoded := make([]byte, cpaRequestIDBase62Width)
	for index := len(encoded) - 1; index >= 0; index-- {
		quotientHigh, remainderHigh := bits.Div64(0, high, uint64(len(cpaRequestIDBase62Alphabet)))
		quotientLow, remainder := bits.Div64(remainderHigh, low, uint64(len(cpaRequestIDBase62Alphabet)))
		encoded[index] = cpaRequestIDBase62Alphabet[remainder]
		high = quotientHigh
		low = quotientLow
	}
	return string(encoded)
}
