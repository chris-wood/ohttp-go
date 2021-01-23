package ohttp

import (
	"testing"

	"github.com/cisco/go-hpke"
	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	privateConfig, err := CreatePrivateConfig(hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
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
