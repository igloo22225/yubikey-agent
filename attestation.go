package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
)

func generateValidationCert(yk *piv.YubiKey, slot piv.Slot) string {
	attest, err := yk.Attest(slot)
	if err != nil {
		log.Fatalf("Unable to attest for slot %s", slot.String())
	}
	intermediate, err := yk.AttestationCertificate()
	if err != nil {
		log.Fatalf("Unable to retrieve intermediate certificate.")
	}
	return fmt.Sprintf("%s|%s",
		base64.StdEncoding.EncodeToString(attest.Raw),
		base64.StdEncoding.EncodeToString(intermediate.Raw))
}

func printKeys(yk *piv.YubiKey, slots []slotConfig, includeAttestations bool) {
	for _, sc := range slots {
		name := slotDisplayName(sc)
		key, err := getPublicKey(yk, sc.Slot)
		if err != nil {
			fmt.Printf("------------------------------\n")
			fmt.Printf("Key (%s): UNUSED\n", name)
			if includeAttestations {
				fmt.Printf("Attestation (%s): N/A\n", name)
			}
		} else {
			fmt.Printf("------------------------------\n")
			label := "Key"
			if sc.Purpose == PurposeEncryption {
				label = "Key [encryption only - will not work for SSH]"
			}
			fmt.Printf("%s (%s): %s", label, name, ssh.MarshalAuthorizedKey(key))
			if includeAttestations {
				fmt.Printf("Attestation (%s): %s\n", name, generateValidationCert(yk, sc.Slot))
			}
		}
	}
	fmt.Println("")
}
