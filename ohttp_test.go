package ohttp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/stretchr/testify/require"
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

func TestRoundTrip(t *testing.T) {
	privateConfig, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")

	client := NewDefaultClient(privateConfig.publicConfig)
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
}

func TestCustomRoundTrip(t *testing.T) {
	privateConfig, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(t, err, "CreatePrivateConfig failed")

	customRequestLabel := "message/app-specific-type req"
	customResponseLabel := "message/app-specific-type rep"

	client := NewCustomClient(privateConfig.publicConfig, customRequestLabel, customResponseLabel)
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
	require.Nil(t, err, "EncapsulateResponse failed")
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

	client := NewDefaultClient(privateConfig.publicConfig)
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

	client := NewDefaultClient(privateConfig.publicConfig)
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

	client := NewDefaultClient(privateConfig.publicConfig)
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

func disableTestDraftVector(t *testing.T) {
	skSEnc := mustUnhex(t, "3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a")
	skEEnc := mustUnhex(t, "bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73")
	configEnc := mustUnhex(t, "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003")
	request := mustUnhex(t, "00034745540568747470730b6578616d706c652e636f6d012f")
	response := mustUnhex(t, "0140c8")
	expectedEncapRequest := mustUnhex(t, "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525")
	expectedEncapResponse := mustUnhex(t, "c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd")
	responseNonce := mustUnhex(t, "4b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472c789e7151fcba46158ca84b04464910d")[32:]

	KEM := hpke.KEM_X25519_HKDF_SHA256

	skR, err := KEM.Scheme().UnmarshalBinaryPrivateKey(skSEnc)
	if err != nil {
		t.Fatal(err)
	}
	skE, err := KEM.Scheme().UnmarshalBinaryPrivateKey(skEEnc)
	if err != nil {
		t.Fatal(err)
	}

	config, err := UnmarshalPublicConfig(configEnc)
	if err != nil {
		t.Fatal(err)
	}
	privateConfig := PrivateConfig{
		seed:         nil,
		publicConfig: config,
		sk:           skR,
		pk:           skR.Public(),
	}

	client := Client{
		config: config,
		skE:    skE,
	}
	server := Gateway{
		keyMap: map[uint8]PrivateConfig{
			config.ID: privateConfig,
		},
	}

	encapsulatedRequest, senderContext, err := client.EncapsulateRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expectedEncapRequest, encapsulatedRequest.Marshal()) {
		t.Fatal("Encapsulated request mismatch")
	}

	decapsulatedRequest, receiverContext, err := server.DecapsulateRequest(encapsulatedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request, decapsulatedRequest) {
		t.Fatal("Decapsulated request mismatch")
	}

	encapsulatedResponse, err := receiverContext.encapsulateResponseWithResponseNonce(response, responseNonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expectedEncapResponse, encapsulatedResponse.Marshal()) {
		t.Fatal("Encapsulated response mismatch")
	}

	decapsulatedResponse, err := senderContext.DecapsulateResponse(encapsulatedResponse)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, decapsulatedResponse) {
		t.Fatal("Decapsulated response mismatch")
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	privateConfig, err := NewConfig(0x00, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	require.Nil(b, err, "CreatePrivateConfig failed")

	client := NewDefaultClient(privateConfig.publicConfig)
	server := NewDefaultGateway([]PrivateConfig{privateConfig})

	rawRequest := []byte("why is the sky blue?")
	rawResponse := []byte("because air is blue")

	var receivedReq []byte
	var req EncapsulatedRequest
	var reqContext EncapsulatedRequestContext
	var resp EncapsulatedResponse
	var respContext DecapsulateRequestContext
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
