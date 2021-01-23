package ohttp

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"strings"
)

type BinaryRequest http.Request
type BinaryResponse http.Response

type frameIndicator uint64

const (
	knownLengthRequestFrame    = frameIndicator(0)
	knownLengthResponseFrame   = frameIndicator(1)
	unknownLengthRequestFrame  = frameIndicator(2)
	unknownLengthResponseFrame = frameIndicator(3)
)

func (f frameIndicator) Marshal() []byte {
	b := new(bytes.Buffer)
	Write(b, uint64(f))
	return b.Bytes()
}

func encodeVarintSlice(b *bytes.Buffer, data []byte) {
	Write(b, uint64(len(data)))
	b.Write([]byte(data))
}

func readVarintSlice(b *bytes.Buffer) ([]byte, error) {
	len, err := Read(b)
	if err != nil {
		return nil, err
	}
	value := make([]byte, len)
	_, err = b.Read(value)
	if err != nil {
		return nil, err
	}

	return value, nil
}

// Known-length message encoding
//
// Message with Known-Length {
// 	Framing (i) = 0..1,
// 	Known-Length Informational Response (..) ...,
// 	Control Data (..),
// 	Known-Length Field Section (..),
// 	Known-Length Content (..),
// 	Known-Length Field Section (..),
// }
//   Known-Length Field Section {
// 	Length (i) = 2..,
// 	Field Line (..) ...,
//   }
//
//   Known-Length Content {
// 	Content Length (i),
// 	Content (..)
//   }
//
//   Known-Length Informational Response {
// 	Informational Response Control Data (..),
// 	Known-Length Field Section (..),
//   }
func (r *BinaryRequest) Marshal() ([]byte, error) {
	b := new(bytes.Buffer)

	// Framing
	b.Write(knownLengthRequestFrame.Marshal())

	// TODO(caw): what do requests do with the "Informational Response Control Data" field? Skip it?

	// Control data
	controlData := createControlData(r)
	b.Write(controlData.Marshal())

	// Header fields
	fields := requestHeaderFields(r)
	encodeVarintSlice(b, fields.Marshal())

	// Content
	if r.Body != nil {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		encodeVarintSlice(b, body)
	} else {
		encodeVarintSlice(b, []byte{})
	}

	// Trailer fields
	// TODO(caw): add support for trailing fields
	Write(b, uint64(0))

	return b.Bytes(), nil
}

// Request Control Data {
// 	Method Length (i),
// 	Method (..),
// 	Scheme Length (i),
// 	Scheme (..),
// 	Authority Length (i),
// 	Authority (..),
// 	Path Length (i),
// 	Path (..),
// }
type requestControlData struct {
	method    string
	scheme    string
	authority string
	path      string
}

func createControlData(r *BinaryRequest) requestControlData {
	return requestControlData{
		method:    r.Method,
		scheme:    r.URL.Scheme,
		authority: r.Host,
		path:      r.URL.Path,
	}
}

func (d requestControlData) Marshal() []byte {
	b := new(bytes.Buffer)

	encodeVarintSlice(b, []byte(d.method))
	encodeVarintSlice(b, []byte(d.scheme))
	encodeVarintSlice(b, []byte(d.authority))
	encodeVarintSlice(b, []byte(d.path))

	return b.Bytes()
}

type field struct {
	name  string
	value string
}

func createHeaderFields(h http.Header) fieldList {
	fields := make([]field, len(h))

	i := 0
	for h, v := range h {
		// Convert the list of values to a string
		b := new(bytes.Buffer)
		for _, s := range v {
			b.Write([]byte(s))
			b.Write([]byte(" "))
		}

		fields[i] = field{
			name:  strings.ToLower(h),
			value: string(b.Bytes()),
		}

		i++
	}

	return fieldList{fields}
}

func requestHeaderFields(r *BinaryRequest) fieldList {
	return createHeaderFields(r.Header)
}

func responseHeaderFields(r *BinaryResponse) fieldList {
	return createHeaderFields(r.Header)
}

func (f field) Marshal() []byte {
	b := new(bytes.Buffer)

	encodeVarintSlice(b, []byte(f.name))
	encodeVarintSlice(b, []byte(f.value))

	return b.Bytes()
}

func (f *field) Unmarshal(b *bytes.Buffer) error {
	name, err := readVarintSlice(b)
	if err != nil {
		return err
	}

	value, err := readVarintSlice(b)
	if err != nil {
		return err
	}

	f.name = strings.ToLower(string(name))
	f.value = string(value)

	return nil
}

type fieldList struct {
	fields []field
}

func (l fieldList) Marshal() []byte {
	b := new(bytes.Buffer)
	for _, f := range l.fields {
		b.Write(f.Marshal())
	}
	body := b.Bytes()

	b = new(bytes.Buffer)
	encodeVarintSlice(b, body)

	return b.Bytes()
}

func (l *fieldList) Unmarshal(b *bytes.Buffer) error {
	body, err := readVarintSlice(b)
	if err != nil {
		return err
	}

	fields := make([]field, 0)

	buf := bytes.NewBuffer(body)
	for {
		if buf.Len() == 0 {
			break
		}

		field := new(field)
		err = field.Unmarshal(buf)
		if err != nil {
			return err
		}

		fields = append(fields, *field)
	}

	l.fields = fields

	return nil
}

///////
// Responses

type finalResponseControlData struct {
	statusCode int // 200..599
}

func (d finalResponseControlData) Marshal() []byte {
	b := new(bytes.Buffer)
	Write(b, uint64(d.statusCode))
	return b.Bytes()
}

type infoResponseControlData struct {
	statusCode int // 100..199
}

func (d infoResponseControlData) Marshal() []byte {
	b := new(bytes.Buffer)
	Write(b, uint64(d.statusCode))
	return b.Bytes()
}

func (r *BinaryResponse) Marshal() ([]byte, error) {
	b := new(bytes.Buffer)

	// Framing
	b.Write(knownLengthResponseFrame.Marshal())

	// TODO(caw): what do requests do with the "Informational Response Control Data" field? Skip it?

	// Response control data
	controlData := finalResponseControlData{r.StatusCode}
	b.Write(controlData.Marshal())

	// Header fields
	fields := responseHeaderFields(r)
	encodeVarintSlice(b, fields.Marshal())

	// Content
	if r.Body != nil {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		encodeVarintSlice(b, body)
	} else {
		encodeVarintSlice(b, []byte{})
	}

	// Trailer fields
	// TODO(caw): add support for trailing fields
	Write(b, uint64(0))

	return b.Bytes(), nil
}

// ///////
// // BinaryResponseWriter interface

// type BinaryResponseWriter struct {
// 	statusCode int
// 	header     http.Header
// 	buffer     bytes.Buffer
// }

// func (w BinaryResponseWriter) Header() http.Header {
// 	return w.header
// }

// func (w BinaryResponseWriter) Write(b []byte) (int, error) {
// 	return w.buffer.Write(b)
// }

// func (w BinaryResponseWriter) WriteHeader(statusCode int) {
// 	w.statusCode = statusCode
// }
