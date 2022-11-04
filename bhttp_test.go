package ohttp

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSimpleRequest(t *testing.T) {
	testURL := "https://example.com:443/path"

	var jsonContent = []byte(`{
		"value": "value",
	}`)
	request, err := http.NewRequest(http.MethodPost, testURL, bytes.NewBuffer(jsonContent))
	require.Nil(t, err, "NewRequest failed")

	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	request.Header.Set("Host", "example.com")
	request.Header.Set("Foo", "Bar")

	binaryRequest := BinaryRequest(*request)
	encodedRequest, err := binaryRequest.Marshal()
	require.Nil(t, err, "Marshal failed")

	recoveredRequest, err := UnmarshalBinaryRequest(encodedRequest)
	require.Nil(t, err, "Unmarshal failed")

	require.Equal(t, binaryRequest.Method, recoveredRequest.Method, "Method mismatch")
	require.Equal(t, binaryRequest.URL.String(), recoveredRequest.URL.String(), "URL mismatch")
	require.Equal(t, binaryRequest.URL.String(), testURL, "URL mismatch (against input)")
	require.Equal(t, recoveredRequest.Header.Get("Foo"), "Bar", "Foo header mismatch")
	require.Equal(t, recoveredRequest.Header.Get("Host"), "example.com", "Host header mismatch")
	require.Equal(t, recoveredRequest.Header.Get("Content-Type"), "application/json; charset=UTF-8", "Content-Type header mismatch")
}

func TestSimpleResponse(t *testing.T) {
	testResponse := &http.Response{
		StatusCode: 200,
		Body:       ioutil.NopCloser(bytes.NewBufferString("test")),
	}
	binaryResponse := CreateBinaryResponse(testResponse)
	_, err := binaryResponse.Marshal()
	if err != nil {
		t.Fatal(err)
	}
}

func createFullRequestFromParts(method string, url string, headers map[string]string, trailers map[string]string, body []byte) *http.Request {
	request, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}
	request.Trailer = make(map[string][]string)

	for key, value := range headers {
		request.Header.Set(key, value)
	}
	for key, value := range trailers {
		request.Trailer.Set(key, value)
	}

	return request
}

func createRequestFromParts(method string, url string, body []byte) *http.Request {
	return createFullRequestFromParts(method, url, nil, nil, body)
}

func TestRequestControlData(t *testing.T) {
	tests := []struct {
		request *http.Request
		enc     []byte
	}{
		{
			request: createRequestFromParts(http.MethodGet, "https://example.com/index.html", nil),
			enc: []byte{
				3, 'G', 'E', 'T',
				5, 'h', 't', 't', 'p', 's',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
			},
		},
		{
			request: createRequestFromParts(http.MethodPost, "https://example.com/index.html", nil),
			enc: []byte{
				4, 'P', 'O', 'S', 'T',
				5, 'h', 't', 't', 'p', 's',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
			},
		},
		{
			request: createRequestFromParts(http.MethodDelete, "https://example.com/index.html", nil),
			enc: []byte{
				6, 'D', 'E', 'L', 'E', 'T', 'E',
				5, 'h', 't', 't', 'p', 's',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
			},
		},
		{
			request: createRequestFromParts(http.MethodHead, "https://example.com/index.html", nil),
			enc: []byte{
				4, 'H', 'E', 'A', 'D',
				5, 'h', 't', 't', 'p', 's',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
			},
		},
		{
			request: createRequestFromParts(http.MethodOptions, "https://example.com/index.html", nil),
			enc: []byte{
				7, 'O', 'P', 'T', 'I', 'O', 'N', 'S',
				5, 'h', 't', 't', 'p', 's',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
			},
		},
		{
			request: createRequestFromParts(http.MethodPatch, "https://example.com/index.html", nil),
			enc: []byte{
				5, 'P', 'A', 'T', 'C', 'H',
				5, 'h', 't', 't', 'p', 's',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
			},
		},
		{
			request: createRequestFromParts(http.MethodPut, "https://example.com/index.html", nil),
			enc: []byte{
				3, 'P', 'U', 'T',
				5, 'h', 't', 't', 'p', 's',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
			},
		},
		{
			request: createRequestFromParts(http.MethodTrace, "https://example.com/index.html", nil),
			enc: []byte{
				5, 'T', 'R', 'A', 'C', 'E',
				5, 'h', 't', 't', 'p', 's',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
			},
		},
		{
			request: createRequestFromParts(http.MethodGet, "http://example.com/index.html", nil),
			enc: []byte{
				3, 'G', 'E', 'T',
				4, 'h', 't', 't', 'p',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
			},
		},
		{
			request: createRequestFromParts(http.MethodGet, "http://example.com", nil),
			enc: []byte{
				3, 'G', 'E', 'T',
				4, 'h', 't', 't', 'p',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				0,
			},
		},
	}

	for _, test := range tests {
		binaryRequest := BinaryRequest(*test.request)
		controlData := createRequestControlData(&binaryRequest)
		encoded := controlData.Marshal()
		require.Equal(t, encoded, test.enc, "Control data encoding mismatch")
	}
}

func TestFieldMarshal(t *testing.T) {
	tests := []struct {
		f   field
		enc []byte
	}{
		{
			f: field{
				name:  "foo",
				value: "bar",
			},
			enc: []byte{0b00000011, 'f', 'o', 'o', 0b00000011, 'b', 'a', 'r'},
		},
		{
			f: field{
				name:  "foo",
				value: "",
			},
			enc: []byte{0b00000011, 'f', 'o', 'o', 0b00000000},
		},
		{
			f: field{
				name:  "",
				value: "bar",
			},
			enc: []byte{0b00000000, 0b00000011, 'b', 'a', 'r'},
		},
	}

	for _, test := range tests {
		enc := test.f.Marshal()
		require.Equal(t, enc, test.enc, "Encoded field mismatch")

		f := new(field)
		err := f.Unmarshal(bytes.NewBuffer(enc))
		require.Nil(t, err, "Unmarshal failure")
		require.Equal(t, f.name, test.f.name, "Field name mismatch")
		require.Equal(t, f.value, test.f.value, "Field valuie mismatch")
	}
}

func TestFieldListMarshal(t *testing.T) {
	tests := []struct {
		l   fieldList
		enc []byte
	}{
		{
			l: fieldList{
				fields: []field{
					{
						name:  "foo",
						value: "bar",
					},
				},
			},
			enc: []byte{0b00000011, 'f', 'o', 'o', 0b00000011, 'b', 'a', 'r'},
		},
	}

	for _, test := range tests {
		enc := test.l.Marshal()
		require.Equal(t, test.enc, enc, "Encoded field list mismatch")

		l := new(fieldList)
		err := l.Unmarshal(bytes.NewBuffer(enc))
		require.Nil(t, err, "Unmarshal failure")
		require.Equal(t, l.fields[0].name, test.l.fields[0].name, "Field name mismatch")
		require.Equal(t, l.fields[0].value, test.l.fields[0].value, "Field valuie mismatch")
	}
}

func TestRequestMarshal(t *testing.T) {
	testHeaderMap := make(map[string]string)
	testHeaderMap["TestHeader"] = "foo" // len("TestHeader") == 10, len("foo") == 3
	testTrailerMap := make(map[string]string)
	testTrailerMap["TestTrailer"] = "bar" // len("TestTrailer") == 11, len("bar") == 3

	tests := []struct {
		request       *http.Request
		enc           []byte
		expectedError error
	}{
		{
			request: createRequestFromParts(http.MethodGet, "https://example.com/index.html", []byte("body")),
			enc: []byte{
				// Framing indicator
				byte(knownLengthRequestFrame),
				// Request Control Data
				3, 'G', 'E', 'T',
				5, 'h', 't', 't', 'p', 's',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
				// Known-Length Field Section (Headers)
				0, // empty list of fields
				// Known-Length Content
				4, 'b', 'o', 'd', 'y',
				// Known-Length Field Section (Trailers)
				0, // empty list of fields
				// Padding
				// empty
			},
		},
		{
			request: createFullRequestFromParts(http.MethodGet, "https://example.com/index.html", testHeaderMap, nil, []byte("body")),
			enc: []byte{
				// Framing indicator
				byte(knownLengthRequestFrame),
				// Request Control Data
				3, 'G', 'E', 'T',
				5, 'h', 't', 't', 'p', 's',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
				// Known-Length Field Section (Headers)
				15,
				10, 't', 'e', 's', 't', 'h', 'e', 'a', 'd', 'e', 'r',
				3, 'f', 'o', 'o',
				// Known-Length Content
				4, 'b', 'o', 'd', 'y',
				// Known-Length Field Section (Trailers)
				0, // empty list of fields
				// Padding
				// empty
			},
		},
		{
			request: createFullRequestFromParts(http.MethodGet, "https://example.com/index.html", testHeaderMap, testTrailerMap, []byte("body")),
			enc: []byte{
				// Framing indicator
				byte(knownLengthRequestFrame),
				// Request Control Data
				3, 'G', 'E', 'T',
				5, 'h', 't', 't', 'p', 's',
				11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				11, '/', 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l',
				// Known-Length Field Section (Headers)
				15,
				10, 't', 'e', 's', 't', 'h', 'e', 'a', 'd', 'e', 'r',
				3, 'f', 'o', 'o',
				// Known-Length Content
				4, 'b', 'o', 'd', 'y',
				// Known-Length Field Section (Trailers)
				16,
				11, 't', 'e', 's', 't', 't', 'r', 'a', 'i', 'l', 'e', 'r',
				3, 'b', 'a', 'r',
				// Padding
				// empty
			},
		},
	}

	for _, test := range tests {
		binaryRequest := BinaryRequest(*test.request)
		encodedRequest, err := binaryRequest.Marshal()
		if test.expectedError == nil {
			require.Equal(t, test.enc, encodedRequest, "Encoded request mismatch")
		} else {
			require.Equal(t, test.expectedError, err, "Expected error mismatch")
		}
	}
}

func createResponseFromParts(statusCode int, headers map[string]string, trailers map[string]string, content []byte) *http.Response {
	resp := &http.Response{
		Body:       ioutil.NopCloser(bytes.NewBuffer(content)),
		StatusCode: statusCode,
		Header:     http.Header{},
		Trailer:    http.Header{},
	}

	for key, value := range headers {
		resp.Header.Set(key, value)
	}
	for key, value := range trailers {
		resp.Trailer.Set(key, value)
	}

	return resp
}

func TestResponseMarshal(t *testing.T) {
	testHeaderMap := make(map[string]string)
	testHeaderMap["TestHeader"] = "foo" // len("TestHeader") == 10, len("foo") == 3
	testTrailerMap := make(map[string]string)
	testTrailerMap["TestTrailer"] = "bar" // len("TestTrailer") == 11, len("bar") == 3

	tests := []struct {
		response      *http.Response
		enc           []byte
		expectedError error
	}{
		{
			response: createResponseFromParts(http.StatusOK, nil, nil, []byte("body")),
			enc: []byte{
				// Framing indicator
				byte(knownLengthResponseFrame),
				// Final Response Control Data
				0x40, http.StatusOK,
				// Known-Length Field Section (Headers)
				0, // empty list of fields
				// Known-Length Content
				4, 'b', 'o', 'd', 'y',
				// Known-Length Field Section (Trailers)
				0, // empty list of fields
				// Padding
				// empty
			},
			expectedError: nil,
		},
		{
			response: createResponseFromParts(http.StatusOK, testHeaderMap, testTrailerMap, []byte("body")),
			enc: []byte{
				// Framing indicator
				byte(knownLengthResponseFrame),
				// Final Response Control Data
				0x40, http.StatusOK,
				// Known-Length Field Section (Headers)
				15,
				10, 't', 'e', 's', 't', 'h', 'e', 'a', 'd', 'e', 'r',
				3, 'f', 'o', 'o',
				// Known-Length Content
				4, 'b', 'o', 'd', 'y',
				// Known-Length Field Section (Trailers)
				16,
				11, 't', 'e', 's', 't', 't', 'r', 'a', 'i', 'l', 'e', 'r',
				3, 'b', 'a', 'r',
				// Padding
				// empty
			},
			expectedError: nil,
		},
		{
			response:      createResponseFromParts(100, nil, nil, []byte("body")),
			enc:           nil,
			expectedError: errInformationalNotSupported,
		},
	}

	for _, test := range tests {
		binaryResponse := BinaryResponse(*test.response)
		encodedResponse, err := binaryResponse.Marshal()
		if test.expectedError == nil {
			require.Equal(t, test.enc, encodedResponse, "Encoded response mismatch")
		} else {
			require.Equal(t, test.expectedError, err, "Expected error mismatch")
		}
	}
}
