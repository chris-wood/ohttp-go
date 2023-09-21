package ohttp

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/cryptobyte"
)

type ConfigCipherSuite struct {
	KDFID  hpke.KDF
	AEADID hpke.AEAD
}

type PublicConfig struct {
	ID             uint8
	KEMID          hpke.KEM
	Suites         []ConfigCipherSuite
	PublicKeyBytes []byte
}

func (c PublicConfig) IsEqual(o PublicConfig) bool {
	if c.ID != o.ID {
		return false
	}
	if c.KEMID != o.KEMID {
		return false
	}
	if !bytes.Equal(c.PublicKeyBytes, o.PublicKeyBytes) {
		return false
	}
	if len(c.Suites) != len(o.Suites) {
		return false
	}
	for i, s := range c.Suites {
		if s.KDFID != o.Suites[i].KDFID {
			return false
		}
		if s.AEADID != o.Suites[i].AEADID {
			return false
		}
	}

	return true
}

type PrivateConfig struct {
	seed         []byte
	publicConfig PublicConfig
	sk           kem.PrivateKey
	pk           kem.PublicKey
}

func (c PrivateConfig) Config() PublicConfig {
	return c.publicConfig
}

func (c PrivateConfig) PrivateKey() kem.PrivateKey {
	return c.sk
}

func NewConfigFromSeed(keyID uint8, kemID hpke.KEM, kdfID hpke.KDF, aeadID hpke.AEAD, seed []byte) (PrivateConfig, error) {
	if !kemID.IsValid() || !kdfID.IsValid() || !aeadID.IsValid() {
		return PrivateConfig{}, fmt.Errorf("invalid ciphersuite")
	}

	pk, sk := kemID.Scheme().DeriveKeyPair(seed)
	cs := ConfigCipherSuite{
		KDFID:  kdfID,
		AEADID: aeadID,
	}

	pkEnc, err := pk.MarshalBinary()
	if err != nil {
		return PrivateConfig{}, err
	}

	publicConfig := PublicConfig{
		ID:             keyID,
		KEMID:          kemID,
		Suites:         []ConfigCipherSuite{cs},
		PublicKeyBytes: pkEnc,
	}

	return PrivateConfig{
		seed:         seed,
		publicConfig: publicConfig,
		sk:           sk,
		pk:           pk,
	}, nil
}

func NewConfig(keyID uint8, kemID hpke.KEM, kdfID hpke.KDF, aeadID hpke.AEAD) (PrivateConfig, error) {
	if !kemID.IsValid() || !kdfID.IsValid() || !aeadID.IsValid() {
		return PrivateConfig{}, fmt.Errorf("invalid ciphersuite")
	}
	ikm := make([]byte, kemID.Scheme().SeedSize())
	rand.Reader.Read(ikm)

	return NewConfigFromSeed(keyID, kemID, kdfID, aeadID, ikm)
}

func (c PublicConfig) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddUint8(c.ID)
	b.AddUint16(uint16(c.KEMID))
	b.AddBytes(c.PublicKeyBytes)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, s := range c.Suites {
			b.AddUint16(uint16(s.KDFID))
			b.AddUint16(uint16(s.AEADID))
		}
	})

	return b.BytesOrPanic()
}

func UnmarshalPublicConfig(data []byte) (PublicConfig, error) {
	s := cryptobyte.String(data)

	var id uint8
	var kemID uint16
	if !s.ReadUint8(&id) ||
		!s.ReadUint16(&kemID) {
		return PublicConfig{}, fmt.Errorf("invalid config")
	}

	kem := hpke.KEM(kemID)
	if !kem.IsValid() {
		return PublicConfig{}, fmt.Errorf("invalid KEM")
	}

	publicKeyBytes := make([]byte, kem.Scheme().PublicKeySize())
	if !s.ReadBytes(&publicKeyBytes, len(publicKeyBytes)) {
		return PublicConfig{}, fmt.Errorf("invalid config")
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return PublicConfig{}, fmt.Errorf("invalid config")
	}
	suites := []ConfigCipherSuite{}
	for !cipherSuites.Empty() {
		var kdfID uint16
		var aeadID uint16
		if !cipherSuites.ReadUint16(&kdfID) ||
			!cipherSuites.ReadUint16(&aeadID) {
			return PublicConfig{}, fmt.Errorf("invalid config")
		}

		// Sanity check validity of the KDF and AEAD values
		kdf := hpke.KDF(kdfID)
		if !kdf.IsValid() {
			return PublicConfig{}, fmt.Errorf("invalid KDF")
		}
		aead := hpke.AEAD(aeadID)
		if !aead.IsValid() {
			return PublicConfig{}, fmt.Errorf("invalid AEAD")
		}

		suites = append(suites, ConfigCipherSuite{
			KDFID:  kdf,
			AEADID: aead,
		})
	}

	return PublicConfig{
		ID:             id,
		KEMID:          kem,
		PublicKeyBytes: publicKeyBytes,
		Suites:         suites,
	}, nil
}
