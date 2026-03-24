// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime/debug"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Version can be set at link time to override debug.BuildInfo.Main.Version,
// which is "(devel)" when building from within the module. See
// golang.org/issue/29814 and golang.org/issue/29228.
var Version string

func init() {
	if Version != "" {
		return
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		Version = buildInfo.Main.Version
		return
	}
	Version = "(unknown version)"
}

func connectForSetup() *piv.YubiKey {
	yk, err := openYK()
	if err != nil {
		log.Fatalln("Failed to connect to the YubiKey:", err)
	}
	return yk
}

func runReset(yk *piv.YubiKey) {
	fmt.Print(`Do you want to reset the PIV applet? This will delete all PIV keys. Type "delete": `)
	var res string
	if _, err := fmt.Scanln(&res); err != nil {
		log.Fatalln("Failed to read response:", err)
	}
	if res != "delete" {
		log.Fatalln("Aborting...")
	}

	fmt.Println("Resetting YubiKey PIV applet...")
	if err := yk.Reset(); err != nil {
		log.Fatalln("Failed to reset YubiKey:", err)
	}
}

func runSetupSlots(yk *piv.YubiKey, slots []slotConfig, forceOverwrite bool, attestation bool) {
	// Check for occupied slots (based on what the user submitted in their config)
	var occupied []slotConfig
	for _, sc := range slots {
		if _, err := yk.Certificate(sc.Slot); err == nil {
			occupied = append(occupied, sc)
		} else if !errors.Is(err, piv.ErrNotFound) {
			log.Fatalf("Failed to access slot %s: %v", slotDisplayName(sc), err)
		}
	}

	if len(occupied) > 0 && !forceOverwrite {
		log.Println("‼️  The following slots already have keys configured:")
		for _, sc := range occupied {
			log.Printf("  %s", slotDisplayName(sc))
		}
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Println("use --really-delete-all-piv-keys ⚠️")
		log.Println("")
		log.Println("To set up an additional slot without wiping, use -slot:")
		log.Println("  yubikey-agent -setup -slot Signature")
		log.Fatalln("Possible slots: Authentication, Signature, KeyManagement, CardAuthentication, or retired slots 82-95")
	}

	// Determine whether this is a fresh device or a previously provisioned one.
	// A fresh device will still have the default management key.
	var key []byte
	if err := yk.SetManagementKey(piv.DefaultManagementKey, piv.DefaultManagementKey); err == nil {
		key = setupPINAndManagementKey(yk)
	} else {
		log.Println("Existing device configuration detected.")
		fmt.Print("PIN: ")
		pin, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Print("\n")
		if err != nil {
			log.Fatalln("Failed to read PIN:", err)
		}
		md, err := yk.Metadata(string(pin))
		if err != nil {
			log.Fatalln("Failed to retrieve management key (wrong PIN?):", err)
		}
		key = *md.ManagementKey
	}

	algorithm := piv.AlgorithmEC256
	if supportsEd25519(yk) {
		algorithm = piv.AlgorithmEd25519
		log.Println("ℹ️  Using Ed25519 (firmware >= 5.7.0)")
	} else {
		log.Println("ℹ️  Using ECDSA P-256 (Ed25519 requires firmware >= 5.7.0)")
	}

	for _, sc := range slots {
		generateAndStoreKey(yk, key, sc.Slot, algorithm, attestation)
	}

	fmt.Println("")
	fmt.Println("✅ Done! This YubiKey is ready to go.")
	fmt.Println("🤏 When the YubiKey blinks, touch it to authorize the login.")
	fmt.Println("")
	fmt.Println("Next steps: ensure yubikey-agent is running via launchd/systemd/...,")
	fmt.Println(`set the SSH_AUTH_SOCK environment variable, and test with "ssh-add -L"`)
	fmt.Println("")
	fmt.Println("💭 Remember: everything breaks, have a backup plan for when this YubiKey does.")
}

func setupPINAndManagementKey(yk *piv.YubiKey) []byte {
	fmt.Println("🔐 The PIN is up to 8 numbers, letters, or symbols. Not just numbers!")
	fmt.Println("❌ The key will be lost if the PIN and PUK are locked after 3 incorrect tries.")
	fmt.Println("")
	fmt.Print("Choose a new PIN/PUK: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	}
	if len(pin) < 6 || len(pin) > 8 {
		log.Fatalln("The PIN needs to be 6-8 characters.")
	}
	fmt.Print("Repeat PIN/PUK: ")
	repeat, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Print("\n")
	if err != nil {
		log.Fatalln("Failed to read PIN:", err)
	} else if !bytes.Equal(repeat, pin) {
		log.Fatalln("PINs don't match!")
	}

	fmt.Println("")
	fmt.Println("🧪 Reticulating splines...")

	key := make([]byte, 24)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	if err := yk.SetManagementKey(piv.DefaultManagementKey, key); err != nil {
		log.Println("‼️  The default Management Key did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	if err := yk.SetMetadata(key, &piv.Metadata{
		ManagementKey: &key,
	}); err != nil {
		log.Fatalln("Failed to store the Management Key on the device:", err)
	}
	if err := yk.SetPIN(piv.DefaultPIN, string(pin)); err != nil {
		log.Println("‼️  The default PIN did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}
	if err := yk.SetPUK(piv.DefaultPUK, string(pin)); err != nil {
		log.Println("‼️  The default PUK did not work")
		log.Println("")
		log.Println("If you know what you're doing, reset PIN, PUK, and")
		log.Println("Management Key to the defaults before retrying.")
		log.Println("")
		log.Println("If you want to wipe all PIV keys and start fresh,")
		log.Fatalln("use --really-delete-all-piv-keys ⚠️")
	}

	return key
}

func generateAndStoreKey(yk *piv.YubiKey, managementKey []byte, slot piv.Slot, algorithm piv.Algorithm, attestation bool) {
	pub, err := yk.GenerateKey(managementKey, slot, piv.Key{
		Algorithm:   algorithm,
		PINPolicy:   piv.PINPolicyOnce,
		TouchPolicy: piv.TouchPolicyAlways,
	})
	if err != nil {
		log.Fatalln("Failed to generate key:", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalln("Failed to generate parent key:", err)
	}
	// Generate and store a certificate in the slot. We do this for two reasons:
	// - We don't want to generate a fresh attestation every time we need the public key
	// - We need to check if the slot is used when setting up (could be done with yk.KeyInfo on firmware >= 5.3.0)
	parent := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"yubikey-agent"},
			OrganizationalUnit: []string{Version},
		},
		PublicKey: priv.Public(),
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "SSH key",
		},
		NotAfter:     time.Now().AddDate(42, 0, 0),
		NotBefore:    time.Now(),
		SerialNumber: randomSerialNumber(),
		KeyUsage:     x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		log.Fatalln("Failed to generate certificate:", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalln("Failed to parse certificate:", err)
	}
	if err := yk.SetCertificate(managementKey, slot, cert); err != nil {
		log.Fatalln("Failed to store certificate:", err)
	}

	sshKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		log.Fatalln("Failed to generate public key:", err)
	}

	fmt.Println("")
	fmt.Printf("🔑 Slot %s SSH public key:\n", slot.String())
	os.Stdout.Write(ssh.MarshalAuthorizedKey(sshKey))
	if attestation {
		fmt.Printf("🧾 Slot %s Attestation:\n", slot.String())
		fmt.Println(generateValidationCert(yk, slot))
	}
}

func supportsEd25519(yk *piv.YubiKey) bool {
	v := yk.Version()
	return v.Major > 5 || (v.Major == 5 && v.Minor >= 7)
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalln("Failed to generate serial number:", err)
	}
	return serialNumber
}
