package ohttp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cisco/go-hpke"
	"github.com/stretchr/testify/require"
)

const (
	outputTestVectorEnvironmentKey = "OHTTP_TEST_VECTORS_OUT"
	inputTestVectorEnvironmentKey  = "OHTTP_TEST_VECTORS_IN"
)

func TestRoundTrip(t *testing.T) {
	privateConfig, err := NewConfig(hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	require.Nil(t, err, "CreatePrivateConfig failed")

	client := OHTTPClient{privateConfig.config}
	server := OHTTPServer{
		keyMap: map[uint8]PrivateConfig{
			privateConfig.config.ID: privateConfig,
		},
	}

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

///////
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

func mustDeserializePriv(t *testing.T, suite hpke.CipherSuite, h string, required bool) hpke.KEMPrivateKey {
	skm := mustUnhex(t, h)
	sk, err := suite.KEM.DeserializePrivateKey(skm)
	if required {
		fatalOnError(t, err, "DeserializePrivate failed")
	}
	return sk
}

func mustSerializePriv(suite hpke.CipherSuite, priv hpke.KEMPrivateKey) string {
	return mustHex(suite.KEM.SerializePrivateKey(priv))
}

func mustDeserializePub(t *testing.T, suite hpke.CipherSuite, h string, required bool) hpke.KEMPublicKey {
	pkm := mustUnhex(t, h)
	pk, err := suite.KEM.DeserializePublicKey(pkm)
	if required {
		fatalOnError(t, err, "DeserializePublicKey failed")
	}
	return pk
}

func mustSerializePub(suite hpke.CipherSuite, pub hpke.KEMPublicKey) string {
	return mustHex(suite.KEM.SerializePublicKey(pub))
}

func mustGenerateKeyPair(t *testing.T, suite hpke.CipherSuite) (hpke.KEMPrivateKey, hpke.KEMPublicKey, []byte) {
	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)
	sk, pk, err := suite.KEM.DeriveKeyPair(ikm)
	fatalOnError(t, err, "Error generating DH key pair")
	return sk, pk, ikm
}

///////
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
	KEMID        hpke.KEMID              `json:"kem_id"`
	KDFID        hpke.KDFID              `json:"kdf_id"`
	AEADID       hpke.AEADID             `json:"aead_id"`
	ConfigSeed   string                  `json:"config_seed"`
	Config       string                  `json:"config"`
	Transactions []transactionTestVector `json:"transactions"`
}

type testVector struct {
	t     *testing.T
	suite hpke.CipherSuite

	kemID  hpke.KEMID
	kdfID  hpke.KDFID
	aeadID hpke.AEADID

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
	// tv.config = []byte(raw.Config)
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

func generateTestVector(t *testing.T, kemID hpke.KEMID, kdfID hpke.KDFID, aeadID hpke.AEADID) testVector {
	privateConfig, err := NewConfig(kemID, kdfID, aeadID)
	require.Nil(t, err, "NewConfig failed")

	client := OHTTPClient{privateConfig.config}
	server := OHTTPServer{
		keyMap: map[uint8]PrivateConfig{
			privateConfig.config.ID: privateConfig,
		},
	}

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
		config:       privateConfig.config,
		transactions: []transactionTestVector{transaction},
	}
}

func verifyTestVector(t *testing.T, vector testVector) {
	privateConfig, err := NewConfigFromSeed(vector.kemID, vector.kdfID, vector.aeadID, vector.configSeed)
	require.Nil(t, err, "NewConfigFromSeed failed")

	client := OHTTPClient{privateConfig.config}
	server := OHTTPServer{
		keyMap: map[uint8]PrivateConfig{
			privateConfig.config.ID: privateConfig,
		},
	}

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
	supportedKEMs := []hpke.KEMID{hpke.DHKEM_X25519}
	supportedKDFs := []hpke.KDFID{hpke.KDF_HKDF_SHA256}
	supportedAEADs := []hpke.AEADID{hpke.AEAD_AESGCM128}

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

// func TestInterop(t *testing.T) {
// 	configSeed := mustUnhex(t, "634b751e5b081ba2836804a466d318811cbf9fe1f65b4249e83c2b7870b2332f")
// 	privateConfig, err := NewConfigFromSeed(hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128, configSeed)
// 	require.Nil(t, err, "NewConfigFromSeed failed")

// 	encodedRequest := mustUnhex(t, "000001000192c1da751e16aaa1426ca3b2fd8e97a05a8e53b67d56bd9b9c573d3e161d05697b153ac23c28b3ed63dbd551f047e412b5083d3093a96de751970fd3d30008423580e3f3a4340fc6dcdd0d6c266592730bf6867743cb6776d52889c030397c7b2dcda6d915630f22c9dc6fe3ae2fb6c110bb2df6a864fcd1d65bf0a35f95771d81f2b2844f666669bfc83e6f1df2c9bd05ff2fea7a2956a608fd048ed7ca27b025b0d2afc70088ce7e13e3995edaffef8259569140b670")
// 	encapRequest, err := UnmarshalEncapsulatedRequest(encodedRequest)
// 	require.Nil(t, err, "UnmarshalEncapsulatedRequest failed")

// 	// client := OHTTPClient{privateConfig.config}
// 	server := OHTTPServer{
// 		keyMap: map[uint8]PrivateConfig{
// 			privateConfig.config.ID: privateConfig,
// 		},
// 	}

// 	request, respContext, err := server.DecapsulateRequest(encapRequest)
// 	require.Nil(t, err, "DecapsulateRequest failed")

// 	resp, err := respContext.EncapsulateResponse(request)
// 	require.Nil(t, err, "EncapsulateResponse failed")

// 	fmt.Println("resp:", hex.EncodeToString(resp.Marshal()))
// }
