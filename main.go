// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

var existingNotificationChannel chan bool

var quietNotify bool

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of yubikey-agent:\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  Setup:\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -setup\n")
		fmt.Fprintf(os.Stderr, "\t\tGenerate a key on the Authentication slot (default).\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -setup -slot SLOT\n")
		fmt.Fprintf(os.Stderr, "\t\tGenerate a key on a specific slot. Can be run on an already-\n")
		fmt.Fprintf(os.Stderr, "\t\tprovisioned YubiKey to add a slot without wiping existing keys.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -setup -touch POLICY\n")
		fmt.Fprintf(os.Stderr, "\t\tSet the touch policy for generated keys. POLICY is one of:\n")
		fmt.Fprintf(os.Stderr, "\t\t  always  - require a physical touch for every operation (default)\n")
		fmt.Fprintf(os.Stderr, "\t\t  never   - never require a touch\n")
		fmt.Fprintf(os.Stderr, "\t\t  cached  - require a touch, then cache for 15 seconds\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -setup -config CONFIG\n")
		fmt.Fprintf(os.Stderr, "\t\tGenerate keys for all slots defined in the config file.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  Dump:\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -dump\n")
		fmt.Fprintf(os.Stderr, "\t\tShow all public keys on the connected YubiKey for slots\n")
		fmt.Fprintf(os.Stderr, "\t\tdefined in the config (or the Authentication slot by default).\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -dump -config CONFIG\n")
		fmt.Fprintf(os.Stderr, "\t\tShow all public keys for slots in the config file. If\n")
		fmt.Fprintf(os.Stderr, "\t\tattestation is enabled in the config, attestation strings\n")
		fmt.Fprintf(os.Stderr, "\t\tare printed alongside each key.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  Agent:\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -l PATH\n")
		fmt.Fprintf(os.Stderr, "\t\tRun the agent with a single socket at PATH, using the\n")
		fmt.Fprintf(os.Stderr, "\t\tAuthentication slot (9a). This is the default behavior.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -l PATH -config CONFIG\n")
		fmt.Fprintf(os.Stderr, "\t\tRun the agent with multiple sockets, one per slot defined\n")
		fmt.Fprintf(os.Stderr, "\t\tin the config file. PATH is used as a base: each named slot\n")
		fmt.Fprintf(os.Stderr, "\t\tproduces PATH-<name> (e.g. -l /tmp/agent.sock with a slot\n")
		fmt.Fprintf(os.Stderr, "\t\tnamed \"main\" creates /tmp/agent.sock-main). A slot with an\n")
		fmt.Fprintf(os.Stderr, "\t\tempty name (\"\") uses PATH as-is, with no suffix.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  Quiet:\n")
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -q\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\t\t(Darwin only) don't beep on press notifications.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "  Slots:\n")
		fmt.Fprintf(os.Stderr, "\tAuthentication     9a   (default when no config is provided)\n")
		fmt.Fprintf(os.Stderr, "\tSignature          9c\n")
		fmt.Fprintf(os.Stderr, "\tKeyManagement      9d\n")
		fmt.Fprintf(os.Stderr, "\tCardAuthentication 9e\n")
		fmt.Fprintf(os.Stderr, "\tRetired            82-95 (hex; use the ID in config or -slot)\n")
		fmt.Fprintf(os.Stderr, "\n")
	}

	socketPath := flag.String("l", "", "agent: path of the UNIX socket to listen on")
	configPath := flag.String("config", "", "agent/setup: path to YAML config file")
	resetFlag := flag.Bool("really-delete-all-piv-keys", false, "setup: reset the PIV applet")
	setupFlag := flag.Bool("setup", false, "setup: configure a new YubiKey")
	setupSlot := flag.String("slot", "", "setup: PIV slot to configure (Authentication, Signature, KeyManagement, CardAuthentication, or retired slot 82-95)")
	touchFlag := flag.String("touch", "always", `setup: touch policy for generated keys ("always", "never", or "cached")`)
	dumpFlag := flag.Bool("dump", false, "dump: show all public keys on the connected YubiKey")
	quietFlag := flag.Bool("q", false, "quiet: Don't send beep on alert.")
	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	if *quietFlag {
		quietNotify = true
	}

	defer wslDetachLastConnectedBusID()

	cfg := parsedConfig{Slots: defaultSlotConfig()}
	if *configPath != "" {
		var err error
		cfg, err = loadConfig(*configPath)
		if err != nil {
			log.Fatalln("Failed to load config:", err)
		}
	}

	if *dumpFlag {
		log.SetFlags(0)
		yk := connectForSetup()
		printKeys(yk, cfg.Slots, cfg.Attestation)
	} else if *setupFlag {
		log.SetFlags(0)
		touchPolicy, err := parseTouchPolicy(*touchFlag)
		if err != nil {
			log.Fatalln(err)
		}
		yk := connectForSetup()
		if *resetFlag {
			runReset(yk)
		}
		if *setupSlot != "" {
			sc, err := slotForSetup(*setupSlot)
			if err != nil {
				log.Fatalln(err)
			}
			runSetupSlots(yk, []slotConfig{sc}, *resetFlag, cfg.Attestation, touchPolicy)
		} else {
			runSetupSlots(yk, cfg.Slots, *resetFlag, cfg.Attestation, touchPolicy)
		}
	} else {
		if *socketPath == "" {
			flag.Usage()
			os.Exit(1)
		}
		runAgent(*socketPath, cfg.Slots)
	}
}

func validateSlotPurposes(yk *piv.YubiKey, slots []slotConfig) error {
	for _, sc := range slots {
		pub, err := getCryptoPublicKey(yk, sc.Slot)
		if err != nil {
			continue
		}
		switch sc.Purpose {
		case PurposeEncryption:
			switch p := pub.(type) {
			case *ecdsa.PublicKey:
				if p.Curve != elliptic.P256() {
					return fmt.Errorf("slot %s is configured for encryption but contains an ECDSA key on curve %s (only NIST P-256 and X25519 are supported)",
						slotDisplayName(sc), p.Curve.Params().Name)
				}
			case *ecdh.PublicKey:
				if p.Curve() != ecdh.X25519() {
					return fmt.Errorf("slot %s is configured for encryption but contains an ECDH key (only NIST P-256 and X25519 are supported)",
						slotDisplayName(sc))
				}
			default:
				return fmt.Errorf("slot %s is configured for encryption but contains a %T key (expected ECDSA P-256 or X25519)",
					slotDisplayName(sc), pub)
			}
		default:
			switch pub.(type) {
			case *ecdsa.PublicKey, ed25519.PublicKey, *rsa.PublicKey:
			default:
				return fmt.Errorf("slot %s is configured for signature but contains a %T key (expected ECDSA, Ed25519, or RSA)",
					slotDisplayName(sc), pub)
			}
		}
	}
	return nil
}

func runAgent(socketPath string, slots []slotConfig) {
	if terminal.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: yubikey-agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd or systemd services.")
	}

	// All agents share a single YubiKey session and mutex, since PIV
	// smartcards can only handle one transaction at a time.
	var agents []*Agent
	yks := &ykSession{mu: &sync.Mutex{}}

	if yk, err := openYK(); err == nil {
		yks.serial, _ = yk.Serial()
		if err := validateSlotPurposes(yk, slots); err != nil {
			yk.Close()
			log.Fatalln("Slot configuration mismatch:", err)
		}
		yks.yk = yk
	}

	for _, sc := range slots {
		agentSocketPath := socketPathForSlot(socketPath, sc)
		a := &Agent{yks: yks, slot: sc.Slot, slotConfig: sc}

		os.Remove(agentSocketPath)
		if err := os.MkdirAll(filepath.Dir(agentSocketPath), 0777); err != nil {
			log.Fatalln("Failed to create UNIX socket folder:", err)
		}
		l, err := net.Listen("unix", agentSocketPath)
		if err != nil {
			log.Fatalln("Failed to listen on UNIX socket:", err)
		}

		log.Printf("Listening on %s (slot %s)", agentSocketPath, slotDisplayName(sc))

		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					type temporary interface {
						Temporary() bool
					}
					if err, ok := err.(temporary); ok && err.Temporary() {
						log.Println("Temporary Accept error, sleeping 1s:", err)
						time.Sleep(1 * time.Second)
						continue
					}
					log.Fatalln("Failed to accept connections:", err)
				}
				go a.serveConn(c)
			}
		}()

		agents = append(agents, a)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	for range c {
		for _, a := range agents {
			a.Close()
		}
	}
}

// ykSession holds the shared YubiKey connection state. All Agent instances
// share a single ykSession so that reconnections are visible across goroutines
// and the physical smartcard is never accessed concurrently.
type ykSession struct {
	yk     *piv.YubiKey
	mu     *sync.Mutex
	serial uint32
}

// Agent services a single PIV slot over its own UNIX socket. Multiple Agents
// share the same ykSession (and its mutex) to coordinate YubiKey access.
type Agent struct {
	yks        *ykSession
	slot       piv.Slot
	slotConfig slotConfig
}

var _ agent.ExtendedAgent = &Agent{}

func (a *Agent) serveConn(c net.Conn) {
	if err := agent.ServeAgent(a, c); err != io.EOF {
		log.Println("Agent client connection ended with error:", err)
	}
}

func healthy(yk *piv.YubiKey) bool {
	// We can't use Serial because it locks the session on older firmwares, and
	// can't use Retries because it fails when the session is unlocked.
	_, err := yk.AttestationCertificate()
	return err == nil
}

func (a *Agent) ensureYK() error {
	err := wslFindAndAttachYubiKey()
	if err != nil {
		return err
	}
	if a.yks.yk == nil || !healthy(a.yks.yk) {
		if a.yks.yk != nil {
			log.Println("Reconnecting to the YubiKey...")
			a.yks.yk.Close()
		} else {
			log.Println("Connecting to the YubiKey...")
		}
		yk, err := a.connectToYK()
		if err != nil {
			return err
		}
		a.yks.yk = yk
	}
	return nil
}

func (a *Agent) connectToYK() (*piv.YubiKey, error) {
	yk, err := openYK()
	if err != nil {
		return nil, err
	}
	// Cache the serial number locally because requesting it on older firmwares
	// requires switching application, which drops the PIN cache.
	a.yks.serial, _ = yk.Serial()
	return yk, nil
}

func openYK() (yk *piv.YubiKey, err error) {
	err = wslFindAndAttachYubiKey()
	if err != nil {
		return nil, err
	}
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no YubiKey detected")
	}
	// TODO: support multiple YubiKeys. For now, select the first one that opens
	// successfully, to skip any internal unused smart card readers.
	for _, card := range cards {
		yk, err = piv.Open(card)
		if err == nil {
			return
		}
	}
	return
}

func (a *Agent) Close() error {
	a.yks.mu.Lock()
	defer a.yks.mu.Unlock()
	if a.yks.yk != nil {
		log.Println("Received HUP, dropping YubiKey transaction...")
		err := a.yks.yk.Close()
		a.yks.yk = nil
		return err
	}
	return nil
}

func (a *Agent) getPIN() (string, error) {
	r, _ := a.yks.yk.Retries()

	// attempt to remove the notification if there's a PIN prompt and notify again later
	removeNotification()

	pin, err := getPIN(a.yks.serial, r)

	// re-notify if a PIN was successfully entered (not cancelled, or errored)
	if err == nil {
		err := showNotification()
		if err != nil {
			// notification failure is not a hard failure
			log.Println("Re-notify failed:", err)
		}
	}

	return pin, err
}

func (a *Agent) List() ([]*agent.Key, error) {
	a.yks.mu.Lock()
	defer a.yks.mu.Unlock()

	if err := wslFindAndAttachYubiKey(); err != nil {
		return nil, err
	}

	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	pk, err := getPublicKey(a.yks.yk, a.slot)
	if err != nil {
		return nil, err
	}
	return []*agent.Key{{
		Format:  pk.Type(),
		Blob:    pk.Marshal(),
		Comment: fmt.Sprintf("YubiKey #%d PIV Slot %s", a.yks.serial, slotDisplayName(a.slotConfig)),
	}}, nil
}

func getPublicKey(yk *piv.YubiKey, slot piv.Slot) (ssh.PublicKey, error) {
	pubKey, err := getCryptoPublicKey(yk, slot)
	if err != nil {
		return nil, err
	}
	// X25519 keys are not supported by ssh.NewPublicKey; wrap them in our
	// custom type that uses the ssh-ed25519 wire format.
	if ecdhPub, ok := pubKey.(*ecdh.PublicKey); ok {
		return newX25519SSHPublicKey(ecdhPub), nil
	}
	switch pubKey.(type) {
	case *ecdsa.PublicKey:
	case *rsa.PublicKey:
	case ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("unexpected public key type: %T", pubKey)
	}
	pk, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to process public key: %w", err)
	}
	return pk, nil
}

func getCryptoPublicKey(yk *piv.YubiKey, slot piv.Slot) (crypto.PublicKey, error) {
	cert, err := yk.Certificate(slot)
	if err != nil {
		if supportsEd25519(yk) {
			// KeyInfo is only available on firmware >= 5.3.0
			// We only need to call this to check for x25519 keys due to them lacking certificates
			// Thus, we'll only call it if there's a chance it could be an x25519 key
			ki, kiErr := yk.KeyInfo(slot)
			if kiErr == nil {
				return ki.PublicKey, nil
			}
		}
		return nil, fmt.Errorf("could not get public key: %w", err)
	}
	return cert.PublicKey, nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.yks.mu.Lock()
	defer a.yks.mu.Unlock()

	if err := wslFindAndAttachYubiKey(); err != nil {
		return nil, err
	}

	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}

	s, err := a.signer()
	if err != nil {
		return nil, err
	}
	return []ssh.Signer{s}, nil
}

func (a *Agent) signer() (*yubiKeySigner, error) {
	pub, err := getCryptoPublicKey(a.yks.yk, a.slot)
	if err != nil {
		return nil, err
	}
	priv, err := a.yks.yk.PrivateKey(
		a.slot,
		pub,
		piv.KeyAuth{PINPrompt: a.getPIN},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare private key: %w", err)
	}
	s, err := NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare signer: %w", err)
	}
	return s, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.yks.mu.Lock()
	defer a.yks.mu.Unlock()

	if err := wslFindAndAttachYubiKey(); err != nil {
		return nil, err
	}

	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}
	defer wslDetachLastConnectedBusID()

	s, err := a.signer()
	if err != nil {
		return nil, err
	}

	pk, err := getPublicKey(a.yks.yk, a.slot)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pk.Marshal(), key.Marshal()) {
		return nil, fmt.Errorf("no private keys match the requested public key")
	}

	ecdhP256 := flags&SignatureFlagECDH != 0
	ecdhX25519 := flags&SignatureFlagX25519ECDH != 0
	isECDH := ecdhP256 || ecdhX25519

	if ecdhP256 && ecdhX25519 {
		return nil, errors.New("cannot set both ECDH and X25519 ECDH flags")
	}

	if isECDH && a.slotConfig.Purpose != PurposeEncryption {
		return nil, fmt.Errorf("ECDH requested on slot %s which is configured for %s, not encryption",
			slotDisplayName(a.slotConfig), a.slotConfig.Purpose)
	}
	if !isECDH && a.slotConfig.Purpose == PurposeEncryption {
		return nil, fmt.Errorf("signature requested on slot %s which is configured for encryption only",
			slotDisplayName(a.slotConfig))
	}

	err = showNotification()
	if err != nil {
		// notification failure is not a hard failure
		log.Println("Notify failed:", err)
	}
	defer removeNotification()

	alg := key.Type()
	switch {
	case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha256 != 0:
		alg = ssh.SigAlgoRSASHA2256
	case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha512 != 0:
		alg = ssh.SigAlgoRSASHA2512
	case alg == ssh.KeyAlgoECDSA256 && ecdhP256:
		alg = KeyAlgoECDH256
	case alg == "x25519" && ecdhX25519:
		alg = KeyAlgoECDHX25519
	}

	log.Printf("Signature requested using key: %s / %s", ssh.MarshalAuthorizedKey(key), slotDisplayName(a.slotConfig))

	var signature *ssh.Signature
	for {
		signature, err = s.SignWithAlgorithm(rand.Reader, data, alg)
		if err == nil || strings.Contains(err.Error(), "cancelled") || strings.Contains(err.Error(), "exit status 1") {
			break
		}
	}
	return signature, err
}

func removeNotification() {
	if existingNotificationChannel != nil {
		existingNotificationChannel <- true
	}
}

func showNotification() error {
	if existingNotificationChannel != nil {
		return errors.New("there is already an active notification")
	}

	title := "YubiKey-Agent touch requested"
	message := "Please touch your YubiKey now."

	legacyMode := false
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		message = strings.ReplaceAll(message, `\`, `\\`)
		message = strings.ReplaceAll(message, `"`, `\"`)
		osascript, err := exec.LookPath("osascript")
		if err != nil {
			return errors.New("failed to find osascript for notification sending")
		}
		button := "This alert will automatically clear itself."
		appleScript := `display dialog "%s" buttons "%s" with title "%s"`
		var commandArgs []string
		if !quietNotify {
			commandArgs = []string{"-e", "beep"}
		}
		cmd = exec.Command(osascript, append(
			commandArgs, "-e", fmt.Sprintf(appleScript, message, button, title))...,
		)
	case "linux":
		// check for WSL
		powershell, err := exec.LookPath(wslPathToPowershell)
		if err == nil {
			psCmd := `$wshShell = New-Object -ComObject WScript.Shell
$options = 0x0 + 0x30 + 0x1000 # OK button + exclamation icon + always-on-top
$wshShell.Popup("%s", 0, "%s", $options)`
			psCmd = fmt.Sprintf(psCmd, message, title)
			cmd = wslGeneratePowershellCmd(powershell, psCmd)
		} else {
			notifySend, err := exec.LookPath("notify-send")
			if err != nil {
				return errors.New("failed to find notify-send for notification sending")
			}
			notifySendVersion, err := exec.Command(notifySend, "-v").Output()
			if err != nil {
				return errors.New("failed to get notify-send version")
			}
			if bytes.Contains(notifySendVersion, []byte(" 0.7")) {
				// notify-send 0.7 on Ubuntu 22.04 unfortunately does not support --wait and therefore
				// does not support management of the notification.
				legacyMode = true
				title = "YubiKey-Agent activated"
				message = "Reminder to touch your YubiKey."
				cmd = exec.Command(notifySend, "-i", "dialog-password", title, message)
			} else {
				cmd = exec.Command(notifySend, "-i", "dialog-password", "--expire-time", "0", "--wait", title, message)
			}
		}
	}

	if cmd == nil {
		return errors.New("failed to determine notification command for operating system")
	}

	err := cmd.Start()
	if err != nil {
		return errors.New("failed to execute notification command")
	}

	go func() {
		if !legacyMode {
			existingNotificationChannel = make(chan bool, 1)
			select {
			// Yubikey typically times out after 15 seconds, so this is unlikely to hit
			case <-time.After(20 * time.Second):
				log.Println("Notification timed out")
			case <-existingNotificationChannel:
			}
			// clears the notification when done on both macOS and Ubuntu 24.04 onwards
			_ = cmd.Process.Signal(os.Interrupt)
		}
		existingNotificationChannel = nil
		_ = cmd.Wait() // required to prevent zombie defunct processes
	}()

	return nil
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

var ErrOperationUnsupported = errors.New("operation unsupported")

func (a *Agent) Add(key agent.AddedKey) error {
	return ErrOperationUnsupported
}
func (a *Agent) Remove(key ssh.PublicKey) error {
	return ErrOperationUnsupported
}
func (a *Agent) RemoveAll() error {
	return a.Close()
}
func (a *Agent) Lock(passphrase []byte) error {
	return ErrOperationUnsupported
}
func (a *Agent) Unlock(passphrase []byte) error {
	return ErrOperationUnsupported
}
