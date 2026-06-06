package plugin

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	zgfxSegmentedSingle    byte = 0xe0
	zgfxSegmentedMultipart byte = 0xe1
	zgfxPacketCompressed   byte = 0x20
	zgfxHistorySize             = 2500000
)

type zgfxToken struct {
	prefixLength uint32
	prefixCode   uint32
	valueBits    uint32
	tokenType    uint32
	valueBase    uint32
}

var zgfxTokenTable = []zgfxToken{
	{1, 0, 8, 0, 0},
	{5, 17, 5, 1, 0}, {5, 18, 7, 1, 32}, {5, 19, 9, 1, 160}, {5, 20, 10, 1, 672}, {5, 21, 12, 1, 1696},
	{5, 24, 0, 0, 0x00}, {5, 25, 0, 0, 0x01},
	{6, 44, 14, 1, 5792}, {6, 45, 15, 1, 22176}, {6, 52, 0, 0, 0x02}, {6, 53, 0, 0, 0x03}, {6, 54, 0, 0, 0xff},
	{7, 92, 18, 1, 54944}, {7, 93, 20, 1, 317088}, {7, 110, 0, 0, 0x04}, {7, 111, 0, 0, 0x05}, {7, 112, 0, 0, 0x06}, {7, 113, 0, 0, 0x07}, {7, 114, 0, 0, 0x08}, {7, 115, 0, 0, 0x09}, {7, 116, 0, 0, 0x0a}, {7, 117, 0, 0, 0x0b}, {7, 118, 0, 0, 0x3a}, {7, 119, 0, 0, 0x3b}, {7, 120, 0, 0, 0x3c}, {7, 121, 0, 0, 0x3d}, {7, 122, 0, 0, 0x3e}, {7, 123, 0, 0, 0x3f}, {7, 124, 0, 0, 0x40}, {7, 125, 0, 0, 0x80},
	{8, 188, 20, 1, 1365664}, {8, 189, 21, 1, 2414240}, {8, 252, 0, 0, 0x0c}, {8, 253, 0, 0, 0x38}, {8, 254, 0, 0, 0x39}, {8, 255, 0, 0, 0x66},
	{9, 380, 22, 1, 4511392}, {9, 381, 23, 1, 8705696}, {9, 382, 24, 1, 17094304},
}

type ZGFXDecoder struct {
	history []byte
	index   int
}

func NewZGFXDecoder() *ZGFXDecoder {
	return &ZGFXDecoder{history: make([]byte, zgfxHistorySize)}
}

func (d *ZGFXDecoder) Decompress(src []byte) ([]byte, error) {
	if len(src) < 1 {
		return nil, errors.New("zgfx empty")
	}
	switch src[0] {
	case zgfxSegmentedSingle:
		return d.decompressSegment(src[1:])
	case zgfxSegmentedMultipart:
		if len(src) < 7 {
			return nil, errors.New("zgfx multipart short")
		}
		count := int(binary.LittleEndian.Uint16(src[1:3]))
		expected := int(binary.LittleEndian.Uint32(src[3:7]))
		pos := 7
		out := make([]byte, 0, expected)
		for i := 0; i < count; i++ {
			if pos+4 > len(src) {
				return nil, errors.New("zgfx segment size short")
			}
			sz := int(binary.LittleEndian.Uint32(src[pos : pos+4]))
			pos += 4
			if sz < 0 || pos+sz > len(src) {
				return nil, errors.New("zgfx segment truncated")
			}
			seg, err := d.decompressSegment(src[pos : pos+sz])
			if err != nil {
				return nil, err
			}
			out = append(out, seg...)
			pos += sz
		}
		if len(out) != expected {
			return nil, fmt.Errorf("zgfx multipart size=%d want %d", len(out), expected)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("zgfx descriptor 0x%02x", src[0])
	}
}

func (d *ZGFXDecoder) decompressSegment(seg []byte) ([]byte, error) {
	if len(seg) < 2 {
		return nil, errors.New("zgfx segment short")
	}
	flags := seg[0]
	body := seg[1:]
	if flags&zgfxPacketCompressed == 0 {
		d.writeHistory(body)
		return append([]byte(nil), body...), nil
	}
	if len(body) < 1 {
		return nil, errors.New("zgfx compressed empty")
	}
	pad := int(body[len(body)-1])
	bitsTotal := (len(body)-1)*8 - pad
	if bitsTotal < 0 {
		return nil, errors.New("zgfx bad padding")
	}
	br := &zgfxBitReader{data: body[:len(body)-1], bitsRemaining: bitsTotal}
	out := make([]byte, 0, 65536)
	for br.bitsRemaining > 0 {
		tok, err := br.nextToken()
		if err != nil {
			return nil, err
		}
		val, err := br.getBits(int(tok.valueBits))
		if err != nil {
			return nil, err
		}
		if tok.tokenType == 0 {
			b := byte(tok.valueBase + val)
			out = append(out, b)
			d.writeHistory([]byte{b})
			continue
		}
		distance := int(tok.valueBase + val)
		if distance == 0 {
			cntBits, err := br.getBits(15)
			if err != nil {
				return nil, err
			}
			count := int(cntBits)
			br.alignByte()
			if count > br.bitsRemaining/8 || count < 0 {
				return nil, errors.New("zgfx unencoded count")
			}
			chunk := br.readBytes(count)
			out = append(out, chunk...)
			d.writeHistory(chunk)
			continue
		}
		bit, err := br.getBits(1)
		if err != nil {
			return nil, err
		}
		count := 3
		if bit != 0 {
			count = 4
			extra := 2
			for {
				b, err := br.getBits(1)
				if err != nil {
					return nil, err
				}
				if b == 0 {
					break
				}
				count *= 2
				extra++
			}
			v, err := br.getBits(extra)
			if err != nil {
				return nil, err
			}
			count += int(v)
		}
		chunk := d.readHistory(distance, count)
		out = append(out, chunk...)
		d.writeHistory(chunk)
	}
	return out, nil
}

func (d *ZGFXDecoder) writeHistory(src []byte) {
	if len(src) == 0 {
		return
	}
	if len(src) > len(d.history) {
		src = src[len(src)-len(d.history):]
	}
	for _, b := range src {
		d.history[d.index] = b
		d.index++
		if d.index == len(d.history) {
			d.index = 0
		}
	}
}

func (d *ZGFXDecoder) readHistory(distance, count int) []byte {
	out := make([]byte, count)
	idx := (d.index + len(d.history) - distance) % len(d.history)
	for i := 0; i < count; i++ {
		out[i] = d.history[idx]
		idx++
		if idx == len(d.history) {
			idx = 0
		}
	}
	return out
}

type zgfxBitReader struct {
	data          []byte
	bitPos        int
	bitsRemaining int
}

func (r *zgfxBitReader) getBits(n int) (uint32, error) {
	if n == 0 {
		return 0, nil
	}
	if n < 0 || n > r.bitsRemaining {
		return 0, errors.New("zgfx bit underrun")
	}
	var v uint32
	for i := 0; i < n; i++ {
		byteIndex := r.bitPos / 8
		shift := 7 - (r.bitPos % 8)
		v = (v << 1) | uint32((r.data[byteIndex]>>shift)&1)
		r.bitPos++
		r.bitsRemaining--
	}
	return v, nil
}

func (r *zgfxBitReader) nextToken() (zgfxToken, error) {
	var prefix uint32
	var have uint32
	for _, tok := range zgfxTokenTable {
		for have < tok.prefixLength {
			b, err := r.getBits(1)
			if err != nil {
				return zgfxToken{}, err
			}
			prefix = (prefix << 1) | b
			have++
		}
		if prefix == tok.prefixCode {
			return tok, nil
		}
	}
	return zgfxToken{}, errors.New("zgfx token not found")
}

func (r *zgfxBitReader) alignByte() {
	drop := r.bitPos % 8
	if drop == 0 {
		return
	}
	n := 8 - drop
	if n > r.bitsRemaining {
		n = r.bitsRemaining
	}
	r.bitPos += n
	r.bitsRemaining -= n
}

func (r *zgfxBitReader) readBytes(n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		v, _ := r.getBits(8)
		out[i] = byte(v)
	}
	return out
}
