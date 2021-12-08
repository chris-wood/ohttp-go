package ohttp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/cisco/go-hpke"

	"golang.org/x/crypto/cryptobyte"
)

type ConfigCipherSuite struct {
	KDFID  hpke.KDFID
	AEADID hpke.AEADID
}

type PublicConfig struct {
	ID             uint8
	KEMID          hpke.KEMID
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
	seed   []byte
	config PublicConfig
	sk     hpke.KEMPrivateKey
	pk     hpke.KEMPublicKey
}

func NewConfigFromSeed(kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID, seed []byte) (PrivateConfig, error) {
	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		return PrivateConfig{}, err
	}

	sk, pk, err := suite.KEM.DeriveKeyPair(seed)
	if err != nil {
		return PrivateConfig{}, err
	}

	cs := ConfigCipherSuite{
		KDFID:  kdfID,
		AEADID: aeadID,
	}

	// TODO(caw): figure out a better API for creating keys with fixed IDs
	publicConfig := PublicConfig{
		ID:             uint8(0x00),
		KEMID:          kemID,
		Suites:         []ConfigCipherSuite{cs},
		PublicKeyBytes: suite.KEM.SerializePublicKey(pk),
	}

	return PrivateConfig{
		seed:   seed,
		config: publicConfig,
		sk:     sk,
		pk:     pk,
	}, nil
}

func NewConfig(kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID) (PrivateConfig, error) {
	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		return PrivateConfig{}, err
	}

	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)

	return NewConfigFromSeed(kemID, kdfID, aeadID, ikm)
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
		return PublicConfig{}, fmt.Errorf("Invalid config")
	}

	kem := hpke.KEMID(kemID)
	suite, err := hpke.AssembleCipherSuite(kem, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		return PublicConfig{}, fmt.Errorf("Invalid config")
	}

	publicKeyBytes := make([]byte, suite.KEM.PublicKeySize())
	if !s.ReadBytes(&publicKeyBytes, len(publicKeyBytes)) {
		return PublicConfig{}, fmt.Errorf("Invalid config")
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return PublicConfig{}, fmt.Errorf("Invalid config")
	}
	suites := []ConfigCipherSuite{}
	for !cipherSuites.Empty() {
		var kdfID uint16
		var aeadID uint16
		if !cipherSuites.ReadUint16(&kdfID) ||
			!cipherSuites.ReadUint16(&aeadID) {
			return PublicConfig{}, fmt.Errorf("Invalid config")
		}

		// Sanity check validity of the KDF and AEAD values
		kdf := hpke.KDFID(kdfID)
		aead := hpke.AEADID(aeadID)
		_, err := hpke.AssembleCipherSuite(kem, kdf, aead)
		if err != nil {
			return PublicConfig{}, fmt.Errorf("Invalid config")
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

type EncapsulatedRequest struct {
	keyID  uint8
	kemID  hpke.KEMID
	kdfID  hpke.KDFID
	aeadID hpke.AEADID
	enc    []byte
	ct     []byte
}

// Encapsulated Request {
// 	Key Identifier (8),
// 	KEM Identifier (16),
// 	KDF Identifier (16),
// 	AEAD Identifier (16),
// 	Encapsulated KEM Shared Secret (8*Nenc),
// 	AEAD-Protected Request (..),
// }
func (r EncapsulatedRequest) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddUint8(r.keyID)
	b.AddUint16(uint16(r.kemID))
	b.AddUint16(uint16(r.kdfID))
	b.AddUint16(uint16(r.aeadID))
	b.AddBytes(r.enc)
	b.AddBytes(r.ct)

	return b.BytesOrPanic()
}

func UnmarshalEncapsulatedRequest(enc []byte) (EncapsulatedRequest, error) {
	b := bytes.NewBuffer(enc)

	keyID, err := b.ReadByte()
	if err != nil {
		return EncapsulatedRequest{}, err
	}

	kemIDBuffer := make([]byte, 2)
	_, err = b.Read(kemIDBuffer)
	if err != nil {
		return EncapsulatedRequest{}, err
	}
	kemID := hpke.KEMID(binary.BigEndian.Uint16(kemIDBuffer))

	kdfIDBuffer := make([]byte, 2)
	_, err = b.Read(kdfIDBuffer)
	if err != nil {
		return EncapsulatedRequest{}, err
	}
	kdfID := hpke.KDFID(binary.BigEndian.Uint16(kdfIDBuffer))

	aeadIDBuffer := make([]byte, 2)
	_, err = b.Read(aeadIDBuffer)
	if err != nil {
		return EncapsulatedRequest{}, err
	}
	aeadID := hpke.AEADID(binary.BigEndian.Uint16(aeadIDBuffer))

	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		return EncapsulatedRequest{}, err
	}

	key := make([]byte, suite.KEM.PublicKeySize())
	_, err = b.Read(key)
	if err != nil {
		return EncapsulatedRequest{}, err
	}

	ct := b.Bytes()

	return EncapsulatedRequest{
		keyID:  uint8(keyID),
		kemID:  kemID,
		kdfID:  kdfID,
		aeadID: aeadID,
		enc:    key,
		ct:     ct,
	}, nil
}

type EncapsulatedRequestContext struct {
	enc     []byte
	suite   hpke.CipherSuite
	context *hpke.SenderContext
}

type EncapsulatedResponse struct {
	raw []byte
}

// Encapsulated Response {
// 	Nonce (Nk),
// 	AEAD-Protected Response (..),
// }
func (r EncapsulatedResponse) Marshal() []byte {
	return r.raw
}

func UnmarshalEncapsulatedResponse(enc []byte) (EncapsulatedResponse, error) {
	return EncapsulatedResponse{
		raw: enc,
	}, nil
}

type EncapsulatedResponseContext struct {
}

type OHTTPClient struct {
	config PublicConfig
}

func (c OHTTPClient) EncapsulateRequest(request []byte) (EncapsulatedRequest, EncapsulatedRequestContext, error) {
	kemID := c.config.KEMID
	kdfID := c.config.Suites[0].KDFID
	aeadID := c.config.Suites[0].AEADID

	suite, err := hpke.AssembleCipherSuite(c.config.KEMID, kdfID, aeadID)
	if err != nil {
		return EncapsulatedRequest{}, EncapsulatedRequestContext{}, err
	}

	pkR, err := suite.KEM.DeserializePublicKey(c.config.PublicKeyBytes)
	if err != nil {
		return EncapsulatedRequest{}, EncapsulatedRequestContext{}, err
	}

	enc, context, err := hpke.SetupBaseS(suite, rand.Reader, pkR, []byte("request"))
	if err != nil {
		return EncapsulatedRequest{}, EncapsulatedRequestContext{}, err
	}

	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(kemID))
	aad := append([]byte{c.config.ID}, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(kdfID))
	aad = append(aad, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(aeadID))
	aad = append(aad, buffer...)

	ct := context.Seal(aad, request)

	return EncapsulatedRequest{
			keyID:  c.config.ID,
			kdfID:  kdfID,
			kemID:  kemID,
			aeadID: aeadID,
			enc:    enc,
			ct:     ct,
		}, EncapsulatedRequestContext{
			enc:     enc,
			suite:   suite,
			context: context,
		}, nil
}

func (c EncapsulatedRequestContext) DecapsulateResponse(response EncapsulatedResponse) ([]byte, error) {
	secret := c.context.Export([]byte("response"), c.suite.AEAD.KeySize())
	prk := c.suite.KDF.Extract(append(c.enc, response.raw[:c.suite.AEAD.KeySize()]...), secret)
	key := c.suite.KDF.Expand(prk, []byte("key"), c.suite.AEAD.KeySize())
	nonce := c.suite.KDF.Expand(prk, []byte("nonce"), c.suite.AEAD.NonceSize())

	cipher, err := c.suite.AEAD.New(key)
	if err != nil {
		return nil, err
	}

	return cipher.Open(nil, nonce, response.raw[c.suite.AEAD.KeySize():], nil)
}

type OHTTPServer struct {
	keyMap map[uint8]PrivateConfig
	// map from IDs to private key(s)
}

type DecapsulateRequestContext struct {
	enc     []byte
	suite   hpke.CipherSuite
	context *hpke.ReceiverContext
}

func (s OHTTPServer) DecapsulateRequest(req EncapsulatedRequest) ([]byte, DecapsulateRequestContext, error) {
	config, ok := s.keyMap[req.keyID]
	if !ok {
		return nil, DecapsulateRequestContext{}, fmt.Errorf("Unknown key ID")
	}

	suite, err := hpke.AssembleCipherSuite(config.config.KEMID, req.kdfID, req.aeadID)
	if err != nil {
		return nil, DecapsulateRequestContext{}, err
	}

	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(config.config.KEMID))
	aad := append([]byte{req.keyID}, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(req.kdfID))
	aad = append(aad, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(req.aeadID))
	aad = append(aad, buffer...)

	context, err := hpke.SetupBaseR(suite, config.sk, req.enc, []byte("request"))
	if err != nil {
		return nil, DecapsulateRequestContext{}, err
	}

	raw, err := context.Open(aad, req.ct)
	if err != nil {
		return nil, DecapsulateRequestContext{}, err
	}

	return raw, DecapsulateRequestContext{
		enc:     req.enc,
		suite:   suite,
		context: context,
	}, nil
}

func (c DecapsulateRequestContext) EncapsulateResponse(response []byte) (EncapsulatedResponse, error) {
	// TODO(caw): implement max(Nk, Nn)
	secret := c.context.Export([]byte("response"), c.suite.AEAD.KeySize())

	responseNonce := make([]byte, c.suite.AEAD.KeySize())
	_, err := rand.Read(responseNonce)
	if err != nil {
		return EncapsulatedResponse{}, err
	}

	prk := c.suite.KDF.Extract(append(c.enc, responseNonce...), secret)
	key := c.suite.KDF.Expand(prk, []byte("key"), c.suite.AEAD.KeySize())
	nonce := c.suite.KDF.Expand(prk, []byte("nonce"), c.suite.AEAD.NonceSize())

	cipher, err := c.suite.AEAD.New(key)
	if err != nil {
		return EncapsulatedResponse{}, err
	}

	ct := cipher.Seal(nil, nonce, response, nil)

	return EncapsulatedResponse{
		raw: append(responseNonce, ct...),
	}, nil
}
