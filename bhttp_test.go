package ohttp

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

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
	// GET /hello.txt HTTP/1.1
	// User-Agent: curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3
	// Host: www.example.com
	// Accept-Language: en, mi

	// 00034745 54056874 74707300 0a2f6865  ..GET.https../he
	// 6c6c6f2e 74787440 6c0a7573 65722d61  llo.txt@l.user-a
	// 67656e74 34637572 6c2f372e 31362e33  gent4curl/7.16.3
	// 206c6962 6375726c 2f372e31 362e3320   libcurl/7.16.3
	// 4f70656e 53534c2f 302e392e 376c207a  OpenSSL/0.9.7l z
	// 6c69622f 312e322e 3304686f 73740f77  lib/1.2.3.host.w
	// 77772e65 78616d70 6c652e63 6f6d0f61  ww.example.com.a
	// 63636570 742d6c61 6e677561 67650665  ccept-language.e
	// 6e2c206d 690000                      n, mi..

	// 00000000  00 03 47 45 54 05 68 74  74 70 73 0f 77 77 77 2e  |..GET.https.www.|
	// 00000010  65 78 61 6d 70 6c 65 2e  63 6f 6d 0a 2f 68 65 6c  |example.com./hel|
	// 00000020  6c 6f 2e 74 78 74 40 5b  40 59 0f 61 63 63 65 70  |lo.txt@[@Y.accep|
	// 00000030  74 2d 6c 61 6e 67 75 61  67 65 07 65 6e 2c 20 6d  |t-language.en, m|
	// 00000040  69 20 0a 75 73 65 72 2d  61 67 65 6e 74 35 63 75  |i .user-agent5cu|
	// 00000050  72 6c 2f 37 2e 31 36 2e  33 20 6c 69 62 63 75 72  |rl/7.16.3 libcur|
	// 00000060  6c 2f 37 2e 31 36 2e 33  20 4f 70 65 6e 53 53 4c  |l/7.16.3 OpenSSL|
	// 00000070  2f 30 2e 39 2e 37 6c 20  7a 6c 69 62 2f 31 2e 32  |/0.9.7l zlib/1.2|
	// 00000080  2e 33 20 00 00                                    |.3 ..|

	req, err := http.NewRequest(http.MethodGet, "https://www.example.com/hello.txt", nil)
	require.Nil(t, err, "NewRequest failed")

	req.Header.Add("User-Agent", "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3")
	// req.Header.Add("Host", "www.example.com") // TODO(caw): fix :authority pseudoheader conflict
	req.Header.Add("Accept-Language", "en, mi")

	// r := BinaryRequest(*req)
	// enc, err := r.Marshal()
	// require.Nil(t, err, "BinaryRequest Marshal failed")
	// fmt.Printf("%s", hex.Dump(enc))
	// fmt.Println(hex.EncodeToString(enc))

	// reqEnc, err := httputil.DumpRequest(req, true)
	// require.Nil(t, err, "Dump request failed")
	// fmt.Println(string(reqEnc))
}

func TestResponseMarshal(t *testing.T) {
	resp := http.Response{
		Body:       ioutil.NopCloser(bytes.NewBufferString("Hello World!")),
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
			"Test-Header":  []string{"foobarbaz"},
		},
	}

	require.Equal(t, resp.StatusCode, http.StatusOK, "Incorrect status code")

	// r := BinaryResponse(resp)
	// enc, err := r.Marshal()
	// require.Nil(t, err, "BinaryResponse Marshal failed")
	// fmt.Printf("%s", hex.Dump(enc))
	// fmt.Println(hex.EncodeToString(enc))

	// respEnc, err := httputil.DumpResponse(&resp, true)
	// require.Nil(t, err, "Dump response failed")
	// fmt.Println(string(respEnc))
}
