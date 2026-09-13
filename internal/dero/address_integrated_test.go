package dero

import "testing"

// TestValidateAddressIntegratedArguments pins the integrated-address (deroi)
// check against three LIVE-verified fixtures. Each was fed to a real R153
// wallet's split_integrated_address, which is a read-only method:
//
//	...k9pvfz92qqgpx3wk  ACCEPTED  -> {"name":"D","datatype":"U","value":0}
//	...k9pv9zqq96rqug    REJECTED  -> Invalid encoding for key 'D'
//	...k8lqqgs6aqkl0     REJECTED  -> cbor: unexpected "break" code
//
// The two rejects have valid bech32 checksums and on-curve keys, so before the
// argument tail was decoded this validator accepted destinations the wallet
// refuses. The bug was invisible to the rest of the suite because every other
// fixture is a plain dero address.
func TestValidateAddressIntegratedArguments(t *testing.T) {
	base := "dero1qykyta6ntpd27nl0yq4xtzaf4ls6p5e9pqu0k2x4x3pqq5xavjsdxqgny8270"

	// Accepted by the live wallet: version + key + CBOR {"DU": 0}.
	if _, err := ValidateAddress("deroi1qykyta6ntpd27nl0yq4xtzaf4ls6p5e9pqu0k2x4x3pqq5xavjsdxqdpvfz92qqk0ryx4"); err != nil {
		t.Fatalf("rejected an integrated address the wallet accepts: %v", err)
	}

	// Rejected by the live wallet: 1-byte key ("D"), which is shorter than the
	// name+datatype pair R153 requires.
	if _, err := ValidateAddress("deroi1qykyta6ntpd27nl0yq4xtzaf4ls6p5e9pqu0k2x4x3pqq5xavjsdxqdpv9zqq0d5mm8"); err == nil {
		t.Fatal("accepted an integrated address with a 1-byte argument key the wallet rejects")
	}

	// Rejected by the live wallet: tail is not CBOR at all.
	if _, err := ValidateAddress("deroi1qykyta6ntpd27nl0yq4xtzaf4ls6p5e9pqu0k2x4x3pqq5xavjsdxq0lqqgsn543at"); err == nil {
		t.Fatal("accepted an integrated address whose arguments are not CBOR")
	}

	// The plain base address must keep working.
	if got, err := ValidateAddress(base); err != nil || got != base {
		t.Fatalf("base address regressed: got %q err=%v", got, err)
	}
}
