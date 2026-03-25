package main

import (
	"crypto"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// SignatureFlagECDH requests ECDH using a P-256 key.
	SignatureFlagECDH agent.SignatureFlags = 0x40000000
	// SignatureFlagX25519ECDH requests ECDH using an X25519 key.
	SignatureFlagX25519ECDH agent.SignatureFlags = 0x20000000
)

const (
	KeyAlgoECDH256    = "ecdh-sha2-nistp256"
	KeyAlgoECDHX25519 = "ecdh-x25519"
)

// ssh.Signer interface
type yubiKeySigner struct {
	ssh.AlgorithmSigner
	crypto.PrivateKey
}

func (s *yubiKeySigner) PublicKey() ssh.PublicKey {
	return s.AlgorithmSigner.PublicKey()
}

func (s *yubiKeySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.AlgorithmSigner.Sign(rand, data)
}

func (s *yubiKeySigner) ecdhP256(data []byte) (*ssh.Signature, error) {
	curve := ecdh.P256()
	peer, err := curve.NewPublicKey(data)
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := s.PrivateKey.(*piv.ECDSAPrivateKey)
	if !ok {
		return nil, fmt.Errorf("ECDH P-256 requested but private key is %T", s.PrivateKey)
	}
	secret, err := ecdsaKey.ECDH(peer)
	if err != nil {
		return nil, err
	}

	// Encode as an SSH string per RFC 4251 section 5.
	var bigEndianLen [4]byte
	binary.BigEndian.PutUint32(bigEndianLen[:], uint32(len(secret)))
	blob := append(bigEndianLen[:], secret...)

	return &ssh.Signature{Format: KeyAlgoECDH256, Blob: blob}, nil
}

func (s *yubiKeySigner) ecdhX25519(data []byte) (*ssh.Signature, error) {
	peer, err := ecdh.X25519().NewPublicKey(data)
	if err != nil {
		return nil, err
	}

	x25519Key, ok := s.PrivateKey.(*piv.X25519PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ECDH X25519 requested but private key is %T", s.PrivateKey)
	}
	secret, err := x25519Key.ECDH(peer)
	if err != nil {
		return nil, err
	}

	var bigEndianLen [4]byte
	binary.BigEndian.PutUint32(bigEndianLen[:], uint32(len(secret)))
	blob := append(bigEndianLen[:], secret...)

	return &ssh.Signature{Format: KeyAlgoECDHX25519, Blob: blob}, nil
}

func (s *yubiKeySigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	switch algorithm {
	case KeyAlgoECDH256:
		return s.ecdhP256(data)
	case KeyAlgoECDHX25519:
		return s.ecdhX25519(data)
	}
	return s.AlgorithmSigner.SignWithAlgorithm(rand, data, algorithm)
}

func NewSignerFromKey(k crypto.PrivateKey) (*yubiKeySigner, error) {
	if x25519Key, ok := k.(*piv.X25519PrivateKey); ok {
		ecdhPub, ok := x25519Key.Public().(*ecdh.PublicKey)
		if !ok {
			return nil, fmt.Errorf("unexpected public key type %T from X25519 private key", x25519Key.Public())
		}
		stub := &x25519StubSigner{pub: newX25519SSHPublicKey(ecdhPub)}
		return &yubiKeySigner{stub, k}, nil
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		return nil, err
	}
	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("signer for %T does not implement AlgorithmSigner", k)
	}
	return &yubiKeySigner{as, k}, nil
}

type x25519StubSigner struct {
	pub ssh.PublicKey
}

func (s *x25519StubSigner) PublicKey() ssh.PublicKey { return s.pub }

func (s *x25519StubSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return nil, errors.New("x25519 keys do not support signing")
}

func (s *x25519StubSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	return nil, fmt.Errorf("x25519 keys do not support signing (algorithm %q)", algorithm)
}

type x25519SSHPublicKey struct {
	pub *ecdh.PublicKey
}

func newX25519SSHPublicKey(pub *ecdh.PublicKey) *x25519SSHPublicKey {
	return &x25519SSHPublicKey{pub: pub}
}

func (k *x25519SSHPublicKey) Type() string { return "x25519" }

func (k *x25519SSHPublicKey) Marshal() []byte {
	keyBytes := k.pub.Bytes()
	typStr := "x25519"
	buf := make([]byte, 4+len(typStr)+4+len(keyBytes))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(typStr)))
	copy(buf[4:4+len(typStr)], typStr)
	binary.BigEndian.PutUint32(buf[4+len(typStr):], uint32(len(keyBytes)))
	copy(buf[4+len(typStr)+4:], keyBytes)
	return buf
}

func (k *x25519SSHPublicKey) Verify(data []byte, sig *ssh.Signature) error {
	return errors.New("x25519 keys do not support signature verification")
}
