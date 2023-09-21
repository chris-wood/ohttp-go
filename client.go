package ohttp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

type Client struct {
	requestLabel  []byte
	responseLabel []byte
	config        PublicConfig
	skE           kem.PrivateKey

	header  EncapsulatedRequestHeader
	context hpke.Sealer
	enc     []byte
}

func newClient(config PublicConfig, requestLabel, responseLabel []byte) (*Client, error) {
	// XXX(caw): maybe split out this stuff into a "Prepare" function, so the constructor is always infallible?
	kemID := config.KEMID
	kdfID := config.Suites[0].KDFID
	aeadID := config.Suites[0].AEADID
	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	pkR, err := kemID.Scheme().UnmarshalBinaryPublicKey(config.PublicKeyBytes)
	if err != nil {
		return nil, err
	}

	// if c.skE != nil {
	// 	suite.KEM.SetEphemeralKeyPair(c.skE)
	// }

	info := requestLabel
	info = append(info, 0x00)
	info = append(info, config.ID)
	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(kemID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(kdfID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(aeadID))
	info = append(info, buffer...)

	sender, err := suite.NewSender(pkR, info)
	if err != nil {
		return nil, err
	}
	enc, context, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Client{
		requestLabel:  []byte(requestLabel),
		responseLabel: []byte(responseLabel),
		config:        config,
		header: EncapsulatedRequestHeader{
			KeyID:  config.ID,
			kdfID:  kdfID,
			kemID:  kemID,
			aeadID: aeadID,
			enc:    enc,
		},
		context: context,
		enc:     enc,
	}, nil
}

func NewDefaultClient(config PublicConfig) (*Client, error) {
	return newClient(config, []byte(defaultLabelRequest), []byte(defaultLabelResponse))
}

func NewCustomClient(config PublicConfig, requestLabel, responseLabel string) (*Client, error) {
	return newClient(config, []byte(requestLabel), []byte(responseLabel))
}

type ChunkedClient struct {
	*Client
}

func NewChunkedClient(config PublicConfig) (*ChunkedClient, error) {
	client, err := newClient(config, []byte(chunkedLabelRequest), []byte(chunkedLabelResponse))
	if err != nil {
		return nil, err
	}
	return &ChunkedClient{
		Client: client,
	}, nil
}

func (c Client) EncapsulateRequest(request []byte) (EncapsulatedRequest, EncapsulatedRequestContext, error) {
	ct, err := c.context.Seal(request, nil)
	if err != nil {
		return EncapsulatedRequest{}, EncapsulatedRequestContext{}, err
	}

	return EncapsulatedRequest{
			hdr: c.header,
			ct:  ct,
		}, EncapsulatedRequestContext{
			responseLabel: []byte(c.responseLabel),
			enc:           c.enc,
			suite:         c.context.Suite(),
			context:       c.context,
		}, nil
}

func (c *ChunkedClient) Prepare() (EncapsulatedRequestHeader, EncapsulatedRequestContext, error) {
	return c.header, EncapsulatedRequestContext{
		responseLabel: []byte(c.responseLabel),
		enc:           c.enc,
		suite:         c.context.Suite(),
		context:       c.context,
	}, nil
}

func (c *EncapsulatedRequestContext) EncapsulateRequestChunk(requestChunk []byte) (EncapsulatedRequestChunk, error) {
	ct, err := c.context.Seal(requestChunk, nil)
	if err != nil {
		return EncapsulatedRequestChunk{}, err
	}

	return EncapsulatedRequestChunk{
		ct: ct,
	}, nil
}

func (c *EncapsulatedRequestContext) EncapsulateFinalRequestChunk(requestChunk []byte) (EncapsulatedRequestChunk, error) {
	ct, err := c.context.Seal(requestChunk, []byte("final"))
	if err != nil {
		return EncapsulatedRequestChunk{}, err
	}

	return EncapsulatedRequestChunk{
		ct: ct,
	}, nil
}

func (c EncapsulatedRequestContext) Prepare(header EncapsulatedResponseHeader) (*EncapsulatedResponseContext, error) {
	// secret = context.Export("message/bhttp response", Nk)
	_, KDF, AEAD := c.suite.Params()

	secret := c.context.Export(c.responseLabel, AEAD.KeySize())

	// response_nonce = random(max(Nn, Nk)), taken from the encapsulated response
	responseNonceLen := max(int(AEAD.KeySize()), 12)
	if responseNonceLen != len(header.responseNonce) {
		// XXX(caw): improve this error
		return nil, fmt.Errorf("Invalid nonce length")
	}

	// salt = concat(enc, response_nonce)
	salt := append(c.enc, header.responseNonce...)

	// prk = Extract(salt, secret)
	prk := KDF.Extract(secret, salt)

	// aead_key = Expand(prk, "key", Nk)
	key := KDF.Expand(prk, []byte(labelResponseKey), AEAD.KeySize())

	// aead_nonce = Expand(prk, "nonce", Nn)
	nonce := KDF.Expand(prk, []byte(labelResponseNonce), 12)

	return &EncapsulatedResponseContext{
		suite:           c.suite,
		aeadKey:         key,
		aeadNonce:       nonce,
		responseCounter: 0,
	}, nil
}

// chunk_nonce = aead_nonce XOR encode(Nn, counter)
func encodeNonce(nonce []byte, counter uint64) []byte {
	buffer := make([]byte, len(nonce))
	binary.BigEndian.PutUint64(buffer[len(nonce)-8:], counter)
	for i, _ := range buffer {
		nonce[i] ^= buffer[i]
	}
	return nonce
}

func decapsulateResponseChunk(suite hpke.Suite, aeadKey, aeadNonce []byte, responseCounter uint64, aad []byte, ct []byte) ([]byte, error) {
	_, _, AEAD := suite.Params()

	// ct = Seal(aead_key, aead_nonce, "", response)
	cipher, err := AEAD.New(aeadKey)
	if err != nil {
		return nil, err
	}

	return cipher.Open(nil, encodeNonce(aeadNonce, responseCounter), ct, aad)
}

func (c *EncapsulatedResponseContext) DecapsulateResponseChunk(chunk EncapsulatedResponseChunk) ([]byte, error) {
	if c.fin {
		panic("Not supported")
	}

	pt, err := decapsulateResponseChunk(c.suite, c.aeadKey, c.aeadNonce, c.responseCounter, nil, chunk.raw)
	if err != nil {
		return nil, err
	}
	c.responseCounter++
	return pt, nil
}

func (c *EncapsulatedResponseContext) DecapsulateFinalResponseChunk(chunk EncapsulatedResponseChunk) ([]byte, error) {
	if c.fin {
		panic("Not supported")
	}
	pt, err := decapsulateResponseChunk(c.suite, c.aeadKey, c.aeadNonce, c.responseCounter, []byte("final"), chunk.raw)
	if err != nil {
		return nil, err
	}
	c.fin = true
	return pt, nil
}

func (c EncapsulatedRequestContext) DecapsulateResponse(response EncapsulatedResponse) ([]byte, error) {
	// secret = context.Export("message/bhttp response", Nk)
	_, KDF, AEAD := c.suite.Params()

	secret := c.context.Export(c.responseLabel, AEAD.KeySize())

	// response_nonce = random(max(Nn, Nk)), taken from the encapsualted response
	responseNonceLen := max(int(AEAD.KeySize()), 12)

	// salt = concat(enc, response_nonce)
	salt := append(c.enc, response.raw[:responseNonceLen]...)

	// prk = Extract(salt, secret)
	prk := KDF.Extract(secret, salt)

	// aead_key = Expand(prk, "key", Nk)
	key := KDF.Expand(prk, []byte(labelResponseKey), AEAD.KeySize())

	// aead_nonce = Expand(prk, "nonce", Nn)
	nonce := KDF.Expand(prk, []byte(labelResponseNonce), 12)

	cipher, err := AEAD.New(key)
	if err != nil {
		return nil, err
	}

	// reponse, error = Open(aead_key, aead_nonce, "", ct)
	return cipher.Open(nil, nonce, response.raw[AEAD.KeySize():], nil)
}
