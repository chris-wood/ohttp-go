package ohttp

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

const (
	outputTestVectorEnvironmentKey = "OHTTP_TEST_VECTORS_OUT"
	inputTestVectorEnvironmentKey  = "OHTTP_TEST_VECTORS_IN"
)

func TestConfigSerialize(t *testing.T) {
	privateConfig, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")

	config := privateConfig.publicConfig

	serializedConfig := config.Marshal()
	recoveredConfig, err := UnmarshalPublicConfig(serializedConfig)
	require.Nil(t, err, "UnmarshalPublicConfig failed")
	require.True(t, config.IsEqual(recoveredConfig), "Config mismatch")
}

func TestConfigListSerialize(t *testing.T) {
	privateConfigA, err := NewConfig(0x01, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")
	privateConfigB, err := NewConfig(0x00, hpke.KEM_X25519_KYBER768_DRAFT00, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")

	gateway := NewDefaultGateway([]PrivateConfig{privateConfigA, privateConfigB})
	serializedConfigs := gateway.MarshalConfigs()

	s := cryptobyte.String(serializedConfigs)

	// Parse and validate configuration A
	var serializedConfigA cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&serializedConfigA) {
		t.Fatal("Failed to decode length-prefix-encoded config")
	}

	recoveredConfigA, err := UnmarshalPublicConfig(serializedConfigA)
	require.Nil(t, err, "UnmarshalPublicConfig failed")
	require.True(t, privateConfigA.publicConfig.IsEqual(recoveredConfigA), "Config A mismatch")

	// Parse and validate configuration B
	var serializedConfigB cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&serializedConfigB) {
		t.Fatal("Failed to decode length-prefix-encoded config")
	}

	recoveredConfigB, err := UnmarshalPublicConfig(serializedConfigB)
	require.Nil(t, err, "UnmarshalPublicConfig failed")
	require.True(t, privateConfigB.publicConfig.IsEqual(recoveredConfigB), "Config B mismatch")

	require.Equal(t, 0, len(s))
}

func TestRoundTrip(t *testing.T) {
	privateConfig, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")

	client, err := NewDefaultClient(privateConfig.publicConfig)
	require.Nil(t, err, "NewDefaultClient failed")
	server := NewDefaultGateway([]PrivateConfig{privateConfig})

	rawRequest := []byte("why is the sky blue?")
	rawResponse := []byte("because air is blue")

	req, reqContext, err := client.EncapsulateRequest(rawRequest)
	require.Nil(t, err, "EncapsulateRequest failed")

	receivedReq, respContext, err := server.DecapsulateRequest(req)
	require.Nil(t, err, "DecapsulateRequest failed")
	require.Equal(t, rawRequest, receivedReq, "Request mismatch")

	resp, err := respContext.EncapsulateResponse(rawResponse)
	require.Nil(t, err, "EncapsulateResponse failed")

	receivedResp, err := reqContext.DecapsulateResponse(resp)
	require.Nil(t, err, "DecapsulateResponse failed")
	require.Equal(t, rawResponse, receivedResp, "Response mismatch")
}

func TestChunkedRoundTrip(t *testing.T) {
	privateConfig, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")

	client, err := NewChunkedClient(privateConfig.publicConfig)
	require.Nil(t, err, "NewChunkedClient failed")
	server := NewChunkedGateway([]PrivateConfig{privateConfig})

	rawRequestChunks := [][]byte{[]byte("hello"), []byte("world")}
	encapsulatedRequestChunks := make([]EncapsulatedRequestChunk, len(rawRequestChunks))
	gatewayRequestChunks := make([][]byte, len(encapsulatedRequestChunks))
	rawResponseChunks := [][]byte{[]byte("foo"), []byte("bar")}
	encapsulatedResponseChunks := make([]EncapsulatedResponseChunk, len(rawResponseChunks))
	clientResponseChunks := make([][]byte, len(encapsulatedResponseChunks))

	// Prepare the client context for chunk encapsulation
	senderHeader, clientRequestContext, err := client.Prepare()

	// Encapsulate each request chunk
	require.Nil(t, err, "Prepare failed")
	for i, _ := range rawRequestChunks {
		if i < len(rawRequestChunks)-1 {
			encapsulatedRequestChunks[i], err = clientRequestContext.EncapsulateRequestChunk(rawRequestChunks[i])
			require.Nil(t, err, "EncapsulateRequestChunk failed")
		} else {
			encapsulatedRequestChunks[i], err = clientRequestContext.EncapsulateFinalRequestChunk(rawRequestChunks[i])
			require.Nil(t, err, "EncapsulateFinalRequestChunk failed")
		}
	}

	// Prepare the server context for request decapsulation and response encapsulation
	gatewayRequestContext, responseHeader, gatewayResponseContext, err := server.Prepare(senderHeader)
	require.Nil(t, err, "Prepare failed")

	// Decapsulate each request chunk
	for i, _ := range encapsulatedRequestChunks {
		if i < len(encapsulatedRequestChunks)-1 {
			gatewayRequestChunks[i], err = gatewayRequestContext.DecapsulateRequestChunk(encapsulatedRequestChunks[i])
			require.Nil(t, err, "DecapsulateRequestChunk failed")
		} else {
			gatewayRequestChunks[i], err = gatewayRequestContext.DecapsulateFinalRequestChunk(encapsulatedRequestChunks[i])
			require.Nil(t, err, "DecapsulateFinalRequestChunk failed")
		}
	}

	// Compare request chunks for equality
	for i, _ := range rawRequestChunks {
		require.Equal(t, rawRequestChunks[i], gatewayRequestChunks[i], "Request chunk mismatch")
	}

	// Encapsulate each response chunk
	for i, _ := range rawResponseChunks {
		if i < len(rawResponseChunks)-1 {
			encapsulatedResponseChunks[i], err = gatewayResponseContext.EncapsulateResponseChunk(rawResponseChunks[i])
			require.Nil(t, err, "EncapsulateResponseChunk failed")
		} else {
			encapsulatedResponseChunks[i], err = gatewayResponseContext.EncapsulateFinalResponseChunk(rawResponseChunks[i])
			require.Nil(t, err, "EncapsulateFinalResponseChunk failed")
		}
	}

	// Prepare the client for response chunk decapsulation
	clientResponseContext, err := clientRequestContext.Prepare(responseHeader)
	require.Nil(t, err, "Prepare failed")

	// Decapsulate each response chunk
	for i, _ := range encapsulatedResponseChunks {
		if i < len(encapsulatedResponseChunks)-1 {
			clientResponseChunks[i], err = clientResponseContext.DecapsulateResponseChunk(encapsulatedResponseChunks[i])
			require.Nil(t, err, "DecapsulateResponseChunk failed")
		} else {
			clientResponseChunks[i], err = clientResponseContext.DecapsulateFinalResponseChunk(encapsulatedResponseChunks[i])
			require.Nil(t, err, "DecapsulateFinalResponseChunk failed")
		}
	}

	// Compare response chunks for equality
	for i, _ := range rawResponseChunks {
		require.Equal(t, rawResponseChunks[i], clientResponseChunks[i], "Response chunk mismatch")
	}
}

func TestCustomRoundTrip(t *testing.T) {
	privateConfig, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")

	customRequestLabel := "message/app-specific-type req"
	customResponseLabel := "message/app-specific-type rep"

	client, err := NewCustomClient(privateConfig.publicConfig, customRequestLabel, customResponseLabel)
	require.Nil(t, err, "NewDefaultClient failed")
	server := NewCustomGateway([]PrivateConfig{privateConfig}, customRequestLabel, customResponseLabel)

	rawRequest := []byte("why is the sky blue?")
	rawResponse := []byte("because air is blue")

	req, reqContext, err := client.EncapsulateRequest(rawRequest)
	require.Nil(t, err, "EncapsulateRequest failed")

	receivedReq, respContext, err := server.DecapsulateRequest(req)
	require.Nil(t, err, "DecapsulateRequest failed")
	require.Equal(t, rawRequest, receivedReq, "Request mismatch")

	resp, err := respContext.EncapsulateResponse(rawResponse)
	require.Nil(t, err, "EncapsulateResponse failed")

	receivedResp, err := reqContext.DecapsulateResponse(resp)
	require.Nil(t, err, "DecapsulateResponse failed")
	require.Equal(t, rawResponse, receivedResp, "Response mismatch")
}

func TestGatewayMultipleConfigsDuplicateKeyId(t *testing.T) {
	defer func() { recover() }()

	privateConfigA, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")
	privateConfigB, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")

	_ = NewDefaultGateway([]PrivateConfig{privateConfigA, privateConfigB})
	t.Errorf("Multiple configs with the same key ID should cause a panic")
}

func TestGatewayMultipleConfigs(t *testing.T) {
	defer func() { recover() }()

	privateConfigA, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")
	privateConfigB, err := NewConfig(0x01, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")

	gateway := NewDefaultGateway([]PrivateConfig{privateConfigA, privateConfigB})
	_, ok := gateway.keyMap[0x00]
	require.True(t, ok)
	_, ok = gateway.keyMap[0x01]
	require.True(t, ok)
}

func TestEncodingMismatchFailure(t *testing.T) {
	privateConfig, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")

	customRequestLabel := "message/dns req"
	customResponseLabel := "message/dns rep"

	client, err := NewDefaultClient(privateConfig.publicConfig)
	require.Nil(t, err, "NewDefaultClient failed")
	server := NewCustomGateway([]PrivateConfig{privateConfig}, customRequestLabel, customResponseLabel)

	rawRequest := []byte("why is the sky blue?")

	req, _, err := client.EncapsulateRequest(rawRequest)
	require.Nil(t, err, "EncapsulateRequest failed")

	receivedReq, _, err := server.DecapsulateRequest(req)
	require.NotNil(t, err, "DecapsulateRequest succeeded when it should have failed")
	require.Nil(t, receivedReq, "Request not nil")
}

// /////
// Infallible Serialize / Deserialize
func fatalOnError(t *testing.T, err error, msg string) {
	realMsg := fmt.Sprintf("%s: %v", msg, err)
	if err != nil {
		if t != nil {
			t.Fatalf(realMsg)
		} else {
			panic(realMsg)
		}
	}
}

func mustUnhex(t *testing.T, h string) []byte {
	out, err := hex.DecodeString(h)
	fatalOnError(t, err, "Unhex failed")
	return out
}

func mustHex(d []byte) string {
	return hex.EncodeToString(d)
}

func mustDeserializePriv(t *testing.T, suite hpke.Suite, h string, required bool) kem.PrivateKey {
	KEM, _, _ := suite.Params()
	skm := mustUnhex(t, h)
	sk, err := KEM.Scheme().UnmarshalBinaryPrivateKey(skm)
	if required {
		fatalOnError(t, err, "DeserializePrivate failed")
	}
	return sk
}

func mustSerializePriv(suite hpke.Suite, priv kem.PrivateKey) string {
	skEnc, err := priv.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return mustHex(skEnc)
}

func mustDeserializePub(t *testing.T, suite hpke.Suite, h string, required bool) kem.PublicKey {
	KEM, _, _ := suite.Params()
	pkm := mustUnhex(t, h)
	pk, err := KEM.Scheme().UnmarshalBinaryPublicKey(pkm)
	if required {
		fatalOnError(t, err, "DeserializePublicKey failed")
	}
	return pk
}

func mustSerializePub(suite hpke.Suite, pub kem.PublicKey) string {
	pkEnc, err := pub.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return mustHex(pkEnc)
}

// /////
// Query/Response transaction test vector structure
type rawTransactionTestVector struct {
	Request              string `json:"request"`
	Response             string `json:"response"`
	EncapsulatedRequest  string `json:"encapsulatedRequest"`
	EncapsulatedResponse string `json:"encapsulatedResponse"`
}

type transactionTestVector struct {
	request              []byte
	response             []byte
	encapsualtedRequest  EncapsulatedRequest
	encapsualtedResponse EncapsulatedResponse
}

func (etv transactionTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawTransactionTestVector{
		Request:              mustHex(etv.request),
		Response:             mustHex(etv.response),
		EncapsulatedRequest:  mustHex(etv.encapsualtedRequest.Marshal()),
		EncapsulatedResponse: mustHex(etv.encapsualtedResponse.Marshal()),
	})
}

func (etv *transactionTestVector) UnmarshalJSON(data []byte) error {
	raw := rawTransactionTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.request = mustUnhex(nil, raw.Request)
	etv.response = mustUnhex(nil, raw.Response)

	encapsulatedRequestBytes := mustUnhex(nil, raw.EncapsulatedRequest)
	encapsulatedResponseBytes := mustUnhex(nil, raw.EncapsulatedResponse)

	etv.encapsualtedRequest, err = UnmarshalEncapsulatedRequest(encapsulatedRequestBytes)
	if err != nil {
		return err
	}
	etv.encapsualtedResponse, err = UnmarshalEncapsulatedResponse(encapsulatedResponseBytes)
	if err != nil {
		return err
	}

	return nil
}

type rawTestVector struct {
	KEMID        hpke.KEM                `json:"kem_id"`
	KDFID        hpke.KDF                `json:"kdf_id"`
	AEADID       hpke.AEAD               `json:"aead_id"`
	ConfigSeed   string                  `json:"config_seed"`
	Config       string                  `json:"config"`
	Transactions []transactionTestVector `json:"transactions"`
}

type testVector struct {
	t     *testing.T
	suite hpke.Suite

	kemID  hpke.KEM
	kdfID  hpke.KDF
	aeadID hpke.AEAD

	configSeed []byte
	config     PublicConfig

	transactions []transactionTestVector
}

func (tv testVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawTestVector{
		KEMID:        tv.kemID,
		KDFID:        tv.kdfID,
		AEADID:       tv.aeadID,
		ConfigSeed:   mustHex(tv.configSeed),
		Config:       mustHex(tv.config.Marshal()),
		Transactions: tv.transactions,
	})
}

func (tv *testVector) UnmarshalJSON(data []byte) error {
	raw := rawTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	tv.kemID = raw.KEMID
	tv.kdfID = raw.KDFID
	tv.aeadID = raw.AEADID
	tv.configSeed = mustUnhex(nil, raw.ConfigSeed)
	tv.transactions = raw.Transactions

	return nil
}

type testVectorArray struct {
	t       *testing.T
	vectors []testVector
}

func (tva testVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *testVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

func generateTestVector(t *testing.T, kemID hpke.KEM, kdfID hpke.KDF, aeadID hpke.AEAD) testVector {
	privateConfig, err := NewConfig(0x00, kemID, kdfID, aeadID)
	require.Nil(t, err, "NewConfig failed")

	client, err := NewDefaultClient(privateConfig.publicConfig)
	require.Nil(t, err, "NewDefaultClient failed")
	server := NewDefaultGateway([]PrivateConfig{privateConfig})

	rawRequest := []byte("why is the sky blue?")
	rawResponse := []byte("because air is blue")

	req, reqContext, err := client.EncapsulateRequest(rawRequest)
	require.Nil(t, err, "EncapsulateRequest failed")

	receivedReq, respContext, err := server.DecapsulateRequest(req)
	require.Nil(t, err, "DecapsulateRequest failed")
	require.Equal(t, rawRequest, receivedReq, "Request mismatch")

	resp, err := respContext.EncapsulateResponse(rawResponse)
	require.Nil(t, err, "EncapsulateResponse failed")

	receivedResp, err := reqContext.DecapsulateResponse(resp)
	require.Nil(t, err, "EncapsulateResponse failed")
	require.Equal(t, rawResponse, receivedResp, "Response mismatch")

	transaction := transactionTestVector{
		request:              rawRequest,
		response:             rawResponse,
		encapsualtedRequest:  req,
		encapsualtedResponse: resp,
	}

	return testVector{
		kemID:        kemID,
		kdfID:        kdfID,
		aeadID:       aeadID,
		configSeed:   privateConfig.seed,
		config:       privateConfig.publicConfig,
		transactions: []transactionTestVector{transaction},
	}
}

func verifyTestVector(t *testing.T, vector testVector) {
	privateConfig, err := NewConfigFromSeed(0x00, vector.kemID, vector.kdfID, vector.aeadID, vector.configSeed)
	require.Nil(t, err, "NewConfigFromSeed failed")

	client, err := NewDefaultClient(privateConfig.publicConfig)
	require.Nil(t, err, "NewDefaultClient failed")
	server := NewDefaultGateway([]PrivateConfig{privateConfig})

	for _, transaction := range vector.transactions {
		req, reqContext, err := client.EncapsulateRequest(transaction.request)
		require.Nil(t, err, "EncapsulateRequest failed")

		receivedReq, respContext, err := server.DecapsulateRequest(req)
		require.Nil(t, err, "DecapsulateRequest failed")
		require.Equal(t, transaction.request, receivedReq, "Request mismatch")

		resp, err := respContext.EncapsulateResponse(transaction.response)
		require.Nil(t, err, "EncapsulateResponse failed")

		receivedResp, err := reqContext.DecapsulateResponse(resp)
		require.Nil(t, err, "EncapsulateResponse failed")
		require.Equal(t, transaction.response, receivedResp, "Response mismatch")
	}
}

func verifyTestVectors(t *testing.T, encoded []byte) {
	vectors := testVectorArray{t: t}
	err := json.Unmarshal(encoded, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, vector := range vectors.vectors {
		verifyTestVector(t, vector)
	}
}

func TestVectorGenerate(t *testing.T) {
	supportedKEMs := []hpke.KEM{hpke.KEM_X25519_HKDF_SHA256}
	supportedKDFs := []hpke.KDF{hpke.KDF_HKDF_SHA256}
	supportedAEADs := []hpke.AEAD{hpke.AEAD_AES128GCM}

	vectors := make([]testVector, 0)
	for _, kemID := range supportedKEMs {
		for _, kdfID := range supportedKDFs {
			for _, aeadID := range supportedAEADs {
				vectors = append(vectors, generateTestVector(t, kemID, kdfID, aeadID))
			}
		}
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyTestVectors(t, encoded)

	var outputFile string
	if outputFile = os.Getenv(outputTestVectorEnvironmentKey); len(outputFile) > 0 {
		err := ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerify(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyTestVectors(t, encoded)
}

func BenchmarkRoundTrip(b *testing.B) {
	privateConfig, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(b, err, "CreatePrivateConfig failed")

	client, err := NewDefaultClient(privateConfig.publicConfig)
	require.Nil(b, err, "NewDefaultClient failed")
	server := NewDefaultGateway([]PrivateConfig{privateConfig})

	rawRequest := []byte("why is the sky blue?")
	rawResponse := []byte("because air is blue")

	var receivedReq []byte
	var req EncapsulatedRequest
	var reqContext EncapsulatedRequestContext
	var resp EncapsulatedResponse
	var respContext *GatewayResponseContext
	b.Run("Encapsulate request", func(b *testing.B) {
		req, reqContext, err = client.EncapsulateRequest(rawRequest)
		require.Nil(b, err, "EncapsulateRequest failed")
	})

	b.Run("Decapsulate request", func(b *testing.B) {
		receivedReq, respContext, err = server.DecapsulateRequest(req)
		require.Nil(b, err, "DecapsulateRequest failed")
		require.Equal(b, rawRequest, receivedReq, "Request mismatch")
	})

	b.Run("Encapsulate response", func(b *testing.B) {
		resp, err = respContext.EncapsulateResponse(rawResponse)
		require.Nil(b, err, "EncapsulateResponse failed")
	})

	b.Run("Decapsulate response", func(b *testing.B) {
		receivedResp, err := reqContext.DecapsulateResponse(resp)
		require.Nil(b, err, "DecapsulateResponse failed")
		require.Equal(b, rawResponse, receivedResp, "Response mismatch")
	})
}
