// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
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
		fmt.Fprintf(os.Stderr, "\tyubikey-agent -setup -config CONFIG\n")
		fmt.Fprintf(os.Stderr, "\t\tGenerate keys for all slots defined in the config file.\n")
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
		fmt.Fprintf(os.Stderr, "  Slots:\n")
		fmt.Fprintf(os.Stderr, "\tAuthentication     9a   (default when no config is provided)\n")
		fmt.Fprintf(os.Stderr, "\tSignature          9c\n")
		fmt.Fprintf(os.Stderr, "\tKeyManagement      9d\n")
		fmt.Fprintf(os.Stderr, "\tCardAuthentication 9e\n")
		fmt.Fprintf(os.Stderr, "\n")
	}

	socketPath := flag.String("l", "", "agent: path of the UNIX socket to listen on")
	configPath := flag.String("config", "", "agent/setup: path to YAML config file for multi-slot support")
	resetFlag := flag.Bool("really-delete-all-piv-keys", false, "setup: reset the PIV applet")
	setupFlag := flag.Bool("setup", false, "setup: configure a new YubiKey")
	setupSlot := flag.String("slot", "", "setup: PIV slot to configure (Authentication, Signature, KeyManagement, CardAuthentication)")
	flag.Parse()

	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	slots := defaultSlotConfig()
	if *configPath != "" {
		var err error
		slots, err = loadConfig(*configPath)
		if err != nil {
			log.Fatalln("Failed to load config:", err)
		}
	}

	if *setupFlag {
		log.SetFlags(0)
		yk := connectForSetup()
		if *resetFlag {
			runReset(yk)
		}
		if *setupSlot != "" {
			sc, err := slotForSetup(*setupSlot)
			if err != nil {
				log.Fatalln(err)
			}
			runSetupSlots(yk, []slotConfig{sc}, *resetFlag)
		} else {
			runSetupSlots(yk, slots, *resetFlag)
		}
	} else {
		if *socketPath == "" {
			flag.Usage()
			os.Exit(1)
		}
		runAgent(*socketPath, slots)
	}
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

	// touchNotification is armed by Sign to show a notification if waiting for
	// more than a few seconds for the touch operation. It is paused and reset
	// by getPIN so it won't fire while waiting for the PIN.
	touchNotification *time.Timer
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

func (a *Agent) maybeReleaseYK() {
	// On macOS, YubiKey 5s persist the PIN cache even across sessions (and even
	// processes), so we can release the lock on the key, to let other
	// applications like age-plugin-yubikey use it.
	if runtime.GOOS != "darwin" || a.yks.yk.Version().Major < 5 {
		return
	}
	if err := a.yks.yk.Close(); err != nil {
		log.Println("Failed to automatically release YubiKey lock:", err)
	}
	a.yks.yk = nil
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
	if a.touchNotification != nil && a.touchNotification.Stop() {
		defer a.touchNotification.Reset(5 * time.Second)
	}
	r, _ := a.yks.yk.Retries()
	return getPIN(a.yks.serial, r)
}

func (a *Agent) List() ([]*agent.Key, error) {
	a.yks.mu.Lock()
	defer a.yks.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}
	defer a.maybeReleaseYK()

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
	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("could not get public key: %w", err)
	}
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
	case *rsa.PublicKey:
	case ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("unexpected public key type: %T", cert.PublicKey)
	}
	pk, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to process public key: %w", err)
	}
	return pk, nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	a.yks.mu.Lock()
	defer a.yks.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}
	defer a.maybeReleaseYK()

	return a.signers()
}

func (a *Agent) signers() ([]ssh.Signer, error) {
	pk, err := getPublicKey(a.yks.yk, a.slot)
	if err != nil {
		return nil, err
	}
	priv, err := a.yks.yk.PrivateKey(
		a.slot,
		pk.(ssh.CryptoPublicKey).CryptoPublicKey(),
		piv.KeyAuth{PINPrompt: a.getPIN},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare private key: %w", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare signer: %w", err)
	}
	return []ssh.Signer{s}, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.yks.mu.Lock()
	defer a.yks.mu.Unlock()
	if err := a.ensureYK(); err != nil {
		return nil, fmt.Errorf("could not reach YubiKey: %w", err)
	}
	defer a.maybeReleaseYK()

	signers, err := a.signers()
	if err != nil {
		return nil, err
	}
	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			continue
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		a.touchNotification = time.NewTimer(5 * time.Second)
		go func() {
			select {
			case <-a.touchNotification.C:
			case <-ctx.Done():
				a.touchNotification.Stop()
				return
			}
			showNotification("Waiting for YubiKey touch...")
		}()

		alg := key.Type()
		switch {
		case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha256 != 0:
			alg = ssh.SigAlgoRSASHA2256
		case alg == ssh.KeyAlgoRSA && flags&agent.SignatureFlagRsaSha512 != 0:
			alg = ssh.SigAlgoRSASHA2512
		}
		// TODO: maybe retry if the PIN is not correct?
		return s.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, data, alg)
	}
	return nil, fmt.Errorf("no private keys match the requested public key")
}

func showNotification(message string) {
	switch runtime.GOOS {
	case "darwin":
		message = strings.ReplaceAll(message, `\`, `\\`)
		message = strings.ReplaceAll(message, `"`, `\"`)
		appleScript := `display notification "%s" with title "yubikey-agent"`
		exec.Command("osascript", "-e", fmt.Sprintf(appleScript, message)).Run()
	case "linux":
		exec.Command("notify-send", "-i", "dialog-password", "yubikey-agent", message).Run()
	}
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
