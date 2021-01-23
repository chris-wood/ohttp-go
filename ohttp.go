package ohttp

import (
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

type PrivateConfig struct {
	config PublicConfig
	sk     hpke.KEMPrivateKey
	pk     hpke.KEMPublicKey
}

func CreatePrivateConfig(kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID) (PrivateConfig, error) {
	suite, err := hpke.AssembleCipherSuite(kemID, kdfID, aeadID)
	if err != nil {
		return PrivateConfig{}, err
	}

	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)
	sk, pk, err := suite.KEM.DeriveKeyPair(ikm)
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
		config: publicConfig,
		sk:     sk,
		pk:     pk,
	}, nil
}

func (c PublicConfig) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddUint8(c.ID)
	b.AddUint16(uint16(c.KEMID))
	for _, s := range c.Suites {
		b.AddUint16(uint16(s.KDFID))
		b.AddUint16(uint16(s.AEADID))
	}
	b.AddBytes(c.PublicKeyBytes)

	result, err := b.Bytes()
	if err != nil {
		panic(err)
	}

	return result
}

type EncapsulatedRequest struct {
	keyID  uint8
	kdfID  hpke.KDFID
	aeadID hpke.AEADID
	enc    []byte
	ct     []byte
}

type EncapsulatedRequestContext struct {
	enc     []byte
	suite   hpke.CipherSuite
	context *hpke.SenderContext
}

type EncapsulatedResponse struct {
	nonce []byte
	ct    []byte
}

type EncapsulatedResponseContext struct {
}

type OHTTPClient struct {
	config PublicConfig
}

func (c OHTTPClient) EncapsulateRequest(request []byte) (EncapsulatedRequest, EncapsulatedRequestContext, error) {
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

	// TODO(caw): we should disucss why we don't fold in the KEMID
	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(kdfID))
	aad := append([]byte{c.config.ID}, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(aeadID))
	aad = append(aad, buffer...)

	ct := context.Seal(aad, request)

	return EncapsulatedRequest{
			keyID:  c.config.ID,
			kdfID:  kdfID,
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
	prk := c.suite.KDF.Extract(append(c.enc, response.nonce...), secret)
	key := c.suite.KDF.Expand(prk, []byte("key"), c.suite.AEAD.KeySize())
	nonce := c.suite.KDF.Expand(prk, []byte("nonce"), c.suite.AEAD.NonceSize())

	cipher, err := c.suite.AEAD.New(key)
	if err != nil {
		return nil, err
	}

	return cipher.Open(nil, nonce, response.ct, nil)
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
	binary.BigEndian.PutUint16(buffer, uint16(req.kdfID))
	aad := append([]byte{req.keyID}, buffer...)
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
		nonce: responseNonce,
		ct:    ct,
	}, nil
}
