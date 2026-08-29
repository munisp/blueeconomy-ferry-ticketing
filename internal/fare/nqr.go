package fare

import (
	"errors"
	"fmt"
	"strings"
)

// NQR (NIBSS Quick Response) payer-scan payload generation for account
// top-ups. NQR is NIBSS's national profile of the EMV Merchant Presented
// Mode QR specification, so the payload is built as EMV TLV with the NIBSS
// NQR application template.
//
// DOCUMENTED SPEC LIMITATION: the public EMV MPM structure (IDs 00/01/52/53/
// 54/58/59/62/63) is verifiable against the EMVCo spec. NIBSS's NQR-specific
// merchant-account template GUI and subfield layout are not publicly
// gazetted; the GUI "NG.NIBSS.NQR" and the 26-template subfield layout below
// are PROVISIONAL and must be confirmed against the NIBSS NQR integrator
// pack before production issuance. The reference (tag 62/05) is
// authoritative for reconciliation either way — it is the topup.reference
// the rail webhook echoes.

// emvTLV renders one EMV tag-length-value (length as two decimal digits).
func emvTLV(tag, value string) string {
	return fmt.Sprintf("%s%02d%s", tag, len(value), value)
}

// crc16CCITT computes the EMV QR CRC (poly 0x1021, init 0xFFFF) over the
// payload including the "6304" marker.
func crc16CCITT(data string) uint16 {
	crc := uint16(0xFFFF)
	for i := 0; i < len(data); i++ {
		crc ^= uint16(data[i]) << 8
		for bit := 0; bit < 8; bit++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// NQRPayload renders the payer-scan EMV QR payload for one NQR top-up.
// Amounts are naira major units with two decimals (EMV tag 54); the ledger
// stays in integer minor units everywhere else.
func NQRPayload(topup TopUp, merchantName string) (string, error) {
	if topup.Channel != TopUpNQR {
		return "", errors.New("NQR payloads require an NQR top-up")
	}
	if topup.AmountNGNMinor <= 0 || topup.Reference == "" {
		return "", errors.New("top-up amount and reference are required")
	}
	if strings.TrimSpace(merchantName) == "" || len(merchantName) > 25 {
		return "", errors.New("merchant name is required (max 25 EMV chars)")
	}
	if topup.AmountNGNMinor%100 != 0 {
		// EMV tag 54 is decimal; kobo fractions are representable, but we
		// keep two-decimal exactness explicit rather than rounding money.
	}
	amountMajor := fmt.Sprintf("%d.%02d", topup.AmountNGNMinor/100, topup.AmountNGNMinor%100)
	// Merchant account information template (26): NIBSS NQR GUI + reference.
	merchantAccount := emvTLV("00", "NG.NIBSS.NQR") + emvTLV("02", topup.Reference)
	additionalData := emvTLV("05", topup.Reference)
	payload := emvTLV("00", "01") + // payload format indicator
		emvTLV("01", "12") + // point of initiation: dynamic (per-transaction)
		emvTLV("26", merchantAccount) +
		emvTLV("52", "5411") + // MCC: financial institutions (top-up)
		emvTLV("53", "566") + // NGN
		emvTLV("54", amountMajor) +
		emvTLV("58", "NG") +
		emvTLV("59", merchantName) +
		emvTLV("62", additionalData)
	payload += "6304"
	return fmt.Sprintf("%s%04X", payload, crc16CCITT(payload)), nil
}
