package ohttp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"golang.org/x/crypto/cryptobyte"
)

type Gateway struct {
	requestLabel  []byte
	responseLabel []byte
	// map from IDs to private key(s)
	keys   []uint8
	keyMap map[uint8]PrivateConfig
}

type ChunkedGateway struct {
	*Gateway
}

func (g Gateway) Config(keyID uint8) (PublicConfig, error) {
	if config, ok := g.keyMap[keyID]; ok {
		return config.Config(), nil
	}
	return PublicConfig{}, fmt.Errorf("unknown keyID %d", keyID)
}

func (g Gateway) Client(keyID uint8) (Client, error) {
	config, err := g.Config(keyID)
	if err != nil {
		return Client{}, err
	}
	return Client{
		requestLabel:  g.requestLabel,
		responseLabel: g.responseLabel,
		config:        config,
	}, nil
}

func createConfigMap(configs []PrivateConfig) ([]uint8, map[uint8]PrivateConfig) {
	configMap := make(map[uint8]PrivateConfig)
	keys := make([]uint8, 0)
	for _, config := range configs {
		_, exists := configMap[config.publicConfig.ID]
		if exists {
			panic("Duplicate config key IDs")
		}
		configMap[config.publicConfig.ID] = config
		keys = append(keys, config.publicConfig.ID)
	}
	return keys, configMap
}

func NewDefaultGateway(configs []PrivateConfig) *Gateway {
	keys, keyMap := createConfigMap(configs)
	return &Gateway{
		requestLabel:  []byte(defaultLabelRequest),
		responseLabel: []byte(defaultLabelResponse),
		keys:          keys,
		keyMap:        keyMap,
	}
}

func NewCustomGateway(configs []PrivateConfig, requestLabel, responseLabel string) *Gateway {
	if requestLabel == "" || responseLabel == "" || requestLabel == responseLabel {
		panic("Invalid request and response labels")
	}

	keys, keyMap := createConfigMap(configs)
	return &Gateway{
		requestLabel:  []byte(requestLabel),
		responseLabel: []byte(responseLabel),
		keys:          keys,
		keyMap:        keyMap,
	}
}

func NewChunkedGateway(configs []PrivateConfig) *ChunkedGateway {
	keys, keyMap := createConfigMap(configs)
	return &ChunkedGateway{
		Gateway: &Gateway{
			requestLabel:  []byte(chunkedLabelRequest),
			responseLabel: []byte(chunkedLabelResponse),
			keys:          keys,
			keyMap:        keyMap,
		},
	}
}

type GatewayResponseContext struct {
	responseLabel []byte
	enc           []byte
	suite         hpke.Suite
	context       hpke.Opener

	responseNonce   []byte
	aeadKey         []byte
	aeadNonce       []byte
	responseCounter uint64
	chunked         bool
	fin             bool
}

func (s Gateway) MatchesConfig(req EncapsulatedRequest) bool {
	_, ok := s.keyMap[req.hdr.KeyID]
	return ok
}

func (s Gateway) MarshalConfigs() []byte {
	b := cryptobyte.NewBuilder(nil)

	for _, id := range s.keys {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(s.keyMap[id].publicConfig.Marshal())
		})
	}
	return b.BytesOrPanic()
}

func prepareResponseContext(context hpke.Context, enc []byte, responseLabel []byte) ([]byte, []byte, []byte, error) {
	// response_nonce = random(max(Nn, Nk))
	_, KDF, AEAD := context.Suite().Params()
	responseNonceLen := max(int(AEAD.KeySize()), 12)
	responseNonce := make([]byte, responseNonceLen)
	_, err := rand.Read(responseNonce)
	if err != nil {
		return nil, nil, nil, err
	}

	// secret = context.Export("message/bhttp response", Nk)
	secret := context.Export(responseLabel, AEAD.KeySize())

	// salt = concat(enc, response_nonce)
	salt := append(enc, responseNonce...)

	// prk = Extract(salt, secret)
	prk := KDF.Extract(secret, salt)

	// aead_key = Expand(prk, "key", Nk)
	key := KDF.Expand(prk, []byte(labelResponseKey), AEAD.KeySize())

	// aead_nonce = Expand(prk, "nonce", Nn)
	nonce := KDF.Expand(prk, []byte(labelResponseNonce), 12)

	return responseNonce, key, nonce, nil
}

func (s Gateway) DecapsulateRequest(req EncapsulatedRequest) ([]byte, *GatewayResponseContext, error) {
	config, ok := s.keyMap[req.hdr.KeyID]
	if !ok {
		return nil, nil, fmt.Errorf("unknown key ID")
	}

	if !config.publicConfig.KEMID.IsValid() || !req.hdr.kdfID.IsValid() || !req.hdr.aeadID.IsValid() {
		return nil, nil, fmt.Errorf("invalid ciphersuite")
	}
	suite := hpke.NewSuite(config.publicConfig.KEMID, req.hdr.kdfID, req.hdr.aeadID)

	info := s.requestLabel
	info = append(info, 0x00)
	info = append(info, req.hdr.KeyID)
	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(req.hdr.kemID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(req.hdr.kdfID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(req.hdr.aeadID))
	info = append(info, buffer...)

	receiver, err := suite.NewReceiver(config.sk, info)
	if err != nil {
		return nil, nil, err
	}
	context, err := receiver.Setup(req.hdr.enc)
	if err != nil {
		return nil, nil, err
	}

	raw, err := context.Open(req.ct, nil)
	if err != nil {
		return nil, nil, err
	}

	responseNonce, key, nonce, err := prepareResponseContext(context, req.hdr.enc, s.responseLabel)
	if err != nil {
		return nil, nil, err
	}

	return raw, &GatewayResponseContext{
		responseLabel: s.responseLabel,
		enc:           req.hdr.enc,
		suite:         suite,
		context:       context,

		aeadKey:       key,
		aeadNonce:     nonce,
		responseNonce: responseNonce,
		chunked:       false,
	}, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type GatewayRequestContext struct {
	opener hpke.Opener
}

func (s *ChunkedGateway) Prepare(header EncapsulatedRequestHeader) (*GatewayRequestContext, EncapsulatedResponseHeader, *GatewayResponseContext, error) {
	config, ok := s.keyMap[header.KeyID]
	if !ok {
		return nil, EncapsulatedResponseHeader{}, nil, fmt.Errorf("unknown key ID")
	}

	if !config.publicConfig.KEMID.IsValid() || !header.kdfID.IsValid() || !header.aeadID.IsValid() {
		return nil, EncapsulatedResponseHeader{}, nil, fmt.Errorf("invalid ciphersuite")
	}
	suite := hpke.NewSuite(config.publicConfig.KEMID, header.kdfID, header.aeadID)

	info := s.requestLabel
	info = append(info, 0x00)
	info = append(info, header.KeyID)
	buffer := make([]byte, 2)
	binary.BigEndian.PutUint16(buffer, uint16(header.kemID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(header.kdfID))
	info = append(info, buffer...)
	binary.BigEndian.PutUint16(buffer, uint16(header.aeadID))
	info = append(info, buffer...)

	receiver, err := suite.NewReceiver(config.sk, info)
	if err != nil {
		return nil, EncapsulatedResponseHeader{}, nil, err
	}
	context, err := receiver.Setup(header.enc)
	if err != nil {
		return nil, EncapsulatedResponseHeader{}, nil, err
	}

	responseNonce, key, nonce, err := prepareResponseContext(context, header.enc, s.responseLabel)
	if err != nil {
		return nil, EncapsulatedResponseHeader{}, nil, err
	}

	return &GatewayRequestContext{
			opener: context,
		}, EncapsulatedResponseHeader{
			responseNonce: responseNonce,
		}, &GatewayResponseContext{
			responseLabel: s.responseLabel,
			enc:           header.enc,
			suite:         suite,
			context:       context,

			aeadKey:         key,
			aeadNonce:       nonce,
			responseCounter: 0,
			chunked:         true,
			fin:             false,
		}, nil
}

func (s *GatewayRequestContext) DecapsulateRequestChunk(requestChunk EncapsulatedRequestChunk) ([]byte, error) {
	return s.opener.Open(requestChunk.ct, nil)
}

func (s *GatewayRequestContext) DecapsulateFinalRequestChunk(requestChunk EncapsulatedRequestChunk) ([]byte, error) {
	return s.opener.Open(requestChunk.ct, []byte("final"))
}

func encapsulateResponse(context hpke.Opener, response, aeadKey, aeadNonce, responseNonce []byte, responseCounter uint64, aad []byte, suite hpke.Suite, responseLabel []byte) ([]byte, error) {
	_, _, AEAD := suite.Params()

	// ct = Seal(aead_key, aead_nonce, "", response)
	cipher, err := AEAD.New(aeadKey)
	if err != nil {
		return nil, err
	}

	ct := cipher.Seal(nil, encodeNonce(aeadNonce, responseCounter), response, aad)

	// enc_response = concat(response_nonce, ct)
	return append(responseNonce, ct...), nil
}

func (c *GatewayResponseContext) EncapsulateResponse(response []byte) (EncapsulatedResponse, error) {
	if c.chunked {
		panic("Operation not supported")
	}
	ct, err := encapsulateResponse(c.context, response, c.aeadKey, c.aeadNonce, c.responseNonce, c.responseCounter, nil, c.suite, c.responseLabel)
	if err != nil {
		return EncapsulatedResponse{}, err
	}
	return EncapsulatedResponse{
		raw: ct,
	}, nil
}

func (c *GatewayResponseContext) EncapsulateResponseChunk(chunk []byte) (EncapsulatedResponseChunk, error) {
	if !c.chunked {
		panic("Operation not supported")
	}

	ct, err := encapsulateResponse(c.context, chunk, c.aeadKey, c.aeadNonce, c.responseNonce, c.responseCounter, nil, c.suite, c.responseLabel)
	if err != nil {
		return EncapsulatedResponseChunk{}, err
	}

	c.responseCounter++

	return EncapsulatedResponseChunk{
		raw: ct,
	}, nil
}

func (c *GatewayResponseContext) EncapsulateFinalResponseChunk(chunk []byte) (EncapsulatedResponseChunk, error) {
	if !c.chunked && !c.fin {
		panic("Operation not supported")
	}

	ct, err := encapsulateResponse(c.context, chunk, c.aeadKey, c.aeadNonce, c.responseNonce, c.responseCounter, []byte("final"), c.suite, c.responseLabel)
	if err != nil {
		return EncapsulatedResponseChunk{}, err
	}
	c.fin = true

	return EncapsulatedResponseChunk{
		raw: ct,
	}, nil
}
