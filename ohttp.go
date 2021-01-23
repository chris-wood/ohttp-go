package ohttp

import (
	"crypto/rand"

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
}

type EncapsulatedRequestContext struct {
}

type EncapsulatedResponse struct {
}

type EncapsulatedResponseContext struct {
}

type OHTTPClient struct {
	config PublicConfig
}

func (c OHTTPClient) EncapsulateRequest(request []byte) (EncapsulatedRequest, EncapsulatedRequestContext, error) {
	return EncapsulatedRequest{}, EncapsulatedRequestContext{}, nil
}

func (c EncapsulatedRequestContext) DecapsulateResponse(response EncapsulatedResponse) ([]byte, error) {
	return nil, nil
}

type OHTTPServer struct {
	// map from IDs to private key(s)
}

type DecapsulateRequestContext struct {
}

func (s OHTTPServer) DecapsulateRequest(EncapsulatedRequest) ([]byte, DecapsulateRequestContext, error) {
	return nil, DecapsulateRequestContext{}, nil
}

func (c DecapsulateRequestContext) EncapsulateResponse(response []byte) (EncapsulatedResponse, error) {
	return EncapsulatedResponse{}, nil
}
