package ohttp

import (
	"bytes"
	"encoding/binary"

	"github.com/cloudflare/circl/hpke"
	"golang.org/x/crypto/cryptobyte"
)

type EncapsulatedRequestHeader struct {
	KeyID  uint8
	kemID  hpke.KEM
	kdfID  hpke.KDF
	aeadID hpke.AEAD
	enc    []byte
}

type EncapsulatedResponseHeader struct {
	responseNonce []byte
}

func (r EncapsulatedRequestHeader) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddUint8(r.KeyID)
	b.AddUint16(uint16(r.kemID))
	b.AddUint16(uint16(r.kdfID))
	b.AddUint16(uint16(r.aeadID))
	b.AddBytes(r.enc)

	return b.BytesOrPanic()
}

type EncapsulatedRequest struct {
	hdr EncapsulatedRequestHeader
	ct  []byte
}

//	Encapsulated Request {
//		Key Identifier (8),
//		KEM Identifier (16),
//		KDF Identifier (16),
//		AEAD Identifier (16),
//		Encapsulated KEM Shared Secret (8*Nenc),
//		AEAD-Protected Request (..),
//	}
func (r EncapsulatedRequest) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	b.AddBytes(r.hdr.Marshal())
	b.AddBytes(r.ct)

	return b.BytesOrPanic()
}

func UnmarshalEncapsulatedRequest(enc []byte) (EncapsulatedRequest, error) {
	b := bytes.NewBuffer(enc)

	keyID, err := b.ReadByte()
	if err != nil {
		return EncapsulatedRequest{}, err
	}

	kemIDBuffer := make([]byte, 2)
	_, err = b.Read(kemIDBuffer)
	if err != nil {
		return EncapsulatedRequest{}, err
	}
	kemID := hpke.KEM(binary.BigEndian.Uint16(kemIDBuffer))

	kdfIDBuffer := make([]byte, 2)
	_, err = b.Read(kdfIDBuffer)
	if err != nil {
		return EncapsulatedRequest{}, err
	}
	kdfID := hpke.KDF(binary.BigEndian.Uint16(kdfIDBuffer))

	aeadIDBuffer := make([]byte, 2)
	_, err = b.Read(aeadIDBuffer)
	if err != nil {
		return EncapsulatedRequest{}, err
	}
	aeadID := hpke.AEAD(binary.BigEndian.Uint16(aeadIDBuffer))

	key := make([]byte, kemID.Scheme().CiphertextSize())
	_, err = b.Read(key)
	if err != nil {
		return EncapsulatedRequest{}, err
	}

	ct := b.Bytes()

	return EncapsulatedRequest{
		hdr: EncapsulatedRequestHeader{
			KeyID:  uint8(keyID),
			kemID:  kemID,
			kdfID:  kdfID,
			aeadID: aeadID,
			enc:    key,
		},
		ct: ct,
	}, nil
}

type EncapsulatedRequestChunk struct {
	ct []byte
}

//	Non-Final Request Chunk {
//		Length (i) = 1..,
//		HPKE-Protected Chunk (..),
//	  }
func (r EncapsulatedRequestChunk) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)

	buffer := bytes.NewBuffer(nil)
	Write(buffer, uint64(len(r.ct)))
	b.AddBytes(buffer.Bytes())
	b.AddBytes(r.ct)

	return b.BytesOrPanic()
}

type EncapsulatedRequestContext struct {
	responseLabel []byte
	enc           []byte
	suite         hpke.Suite
	context       hpke.Sealer
}

type EncapsulatedResponse struct {
	raw []byte
}

type EncapsulatedResponseChunk struct {
	raw []byte
}

//	Encapsulated Response {
//		Nonce (Nk),
//		AEAD-Protected Response (..),
//	}
func (r EncapsulatedResponse) Marshal() []byte {
	return r.raw
}

func UnmarshalEncapsulatedResponse(enc []byte) (EncapsulatedResponse, error) {
	return EncapsulatedResponse{
		raw: enc,
	}, nil
}

type EncapsulatedResponseContext struct {
	suite           hpke.Suite
	aeadKey         []byte
	aeadNonce       []byte
	responseCounter uint64
	fin             bool
}
