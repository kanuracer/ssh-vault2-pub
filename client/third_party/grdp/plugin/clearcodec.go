package plugin

import (
	"encoding/binary"
	"fmt"
)

type ClearCodecDecoder struct {
	nextSeq byte
	haveSeq bool
}

func NewClearCodecDecoder() *ClearCodecDecoder { return &ClearCodecDecoder{} }

func (d *ClearCodecDecoder) Decode(payload []byte, width, height int) ([]byte, error) {
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("invalid clearcodec size %dx%d", width, height)
	}
	if len(payload) < 14 {
		return nil, fmt.Errorf("clearcodec payload too short: %d", len(payload))
	}
	seq := payload[1]
	if !d.haveSeq {
		d.nextSeq = seq
		d.haveSeq = true
	}
	if seq != d.nextSeq {
		d.nextSeq = seq
	}
	d.nextSeq = seq + 1
	residualLen := int(binary.LittleEndian.Uint32(payload[2:6]))
	bandsLen := int(binary.LittleEndian.Uint32(payload[6:10]))
	subLen := int(binary.LittleEndian.Uint32(payload[10:14]))
	p := 14 + residualLen + bandsLen
	if residualLen < 0 || bandsLen < 0 || subLen < 0 || p+subLen > len(payload) {
		return nil, fmt.Errorf("clearcodec subcodec length out of range")
	}
	out := make([]byte, width*height*4)
	if err := decodeClearCodecSubcodecs(payload[p:p+subLen], width, height, out); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeClearCodecSubcodecs(payload []byte, dstW, dstH int, out []byte) error {
	p := 0
	for p < len(payload) {
		if len(payload)-p < 13 {
			return fmt.Errorf("clearcodec subcodec header truncated")
		}
		x := int(binary.LittleEndian.Uint16(payload[p : p+2]))
		y := int(binary.LittleEndian.Uint16(payload[p+2 : p+4]))
		w := int(binary.LittleEndian.Uint16(payload[p+4 : p+6]))
		h := int(binary.LittleEndian.Uint16(payload[p+6 : p+8]))
		dataLen := int(binary.LittleEndian.Uint32(payload[p+8 : p+12]))
		subcodec := payload[p+12]
		p += 13
		if dataLen < 0 || p+dataLen > len(payload) {
			return fmt.Errorf("clearcodec subcodec data truncated")
		}
		if x < 0 || y < 0 || w <= 0 || h <= 0 || x+w > dstW || y+h > dstH {
			return fmt.Errorf("clearcodec subcodec rect out of bounds")
		}
		switch subcodec {
		case 0:
			if dataLen != w*h*3 {
				return fmt.Errorf("clearcodec bgr24 length=%d want=%d", dataLen, w*h*3)
			}
			copyBGR24ToRGBA(payload[p:p+dataLen], w, h, out, dstW, x, y)
		case 2:
			if err := decodeClearCodecRLEX(payload[p:p+dataLen], w, h, out, dstW, x, y); err != nil {
				return err
			}
		default:
			return fmt.Errorf("clearcodec subcodec %d not implemented", subcodec)
		}
		p += dataLen
	}
	return nil
}

func decodeClearCodecRLEX(src []byte, w, h int, out []byte, dstW, dstX, dstY int) error {
	if len(src) < 4 || w <= 0 || h <= 0 {
		return fmt.Errorf("clearcodec rlex short")
	}
	paletteCount := int(src[0])
	if paletteCount < 1 || paletteCount > 127 || len(src) < 1+paletteCount*3 {
		return fmt.Errorf("clearcodec rlex palette count=%d", paletteCount)
	}
	palette := make([][4]byte, paletteCount)
	p := 1
	for i := 0; i < paletteCount; i++ {
		b, g, r := src[p], src[p+1], src[p+2]
		palette[i] = [4]byte{r, g, b, 255}
		p += 3
	}
	numBits := clearLog2Floor(paletteCount-1) + 1
	pixelIndex := 0
	pixelCount := w * h
	mask := byte((1 << numBits) - 1)
	for p < len(src) {
		if p+2 > len(src) {
			return fmt.Errorf("clearcodec rlex truncated")
		}
		tmp := src[p]
		runLength := uint32(src[p+1])
		p += 2
		if runLength >= 0xff {
			if p+2 > len(src) {
				return fmt.Errorf("clearcodec rlex run16 truncated")
			}
			runLength = uint32(binary.LittleEndian.Uint16(src[p : p+2]))
			p += 2
			if runLength >= 0xffff {
				if p+4 > len(src) {
					return fmt.Errorf("clearcodec rlex run32 truncated")
				}
				runLength = binary.LittleEndian.Uint32(src[p : p+4])
				p += 4
			}
		}
		suiteDepth := int((tmp >> numBits) & byte((1<<(8-numBits))-1))
		stopIndex := int(tmp & mask)
		startIndex := stopIndex - suiteDepth
		if startIndex < 0 || stopIndex >= paletteCount {
			return fmt.Errorf("clearcodec rlex index range")
		}
		for i := 0; i < int(runLength); i++ {
			if pixelIndex >= pixelCount {
				return fmt.Errorf("clearcodec rlex pixel overflow")
			}
			putRLEXPixel(out, dstW, dstX, dstY, w, pixelIndex, palette[startIndex])
			pixelIndex++
		}
		for i := 0; i <= suiteDepth; i++ {
			if pixelIndex >= pixelCount {
				return fmt.Errorf("clearcodec rlex suite overflow")
			}
			putRLEXPixel(out, dstW, dstX, dstY, w, pixelIndex, palette[startIndex+i])
			pixelIndex++
		}
	}
	if pixelIndex != pixelCount {
		return fmt.Errorf("clearcodec rlex pixels=%d want=%d", pixelIndex, pixelCount)
	}
	return nil
}

func clearLog2Floor(v int) int {
	n := 0
	for v > 1 {
		v >>= 1
		n++
	}
	return n
}

func putRLEXPixel(out []byte, dstW, dstX, dstY, subW, pixelIndex int, c [4]byte) {
	x := pixelIndex % subW
	y := pixelIndex / subW
	di := ((dstY+dy(y))*dstW + dstX + x) * 4
	out[di+0], out[di+1], out[di+2], out[di+3] = c[0], c[1], c[2], c[3]
}

func dy(y int) int { return y }

func copyBGR24ToRGBA(src []byte, w, h int, dst []byte, dstW, dstX, dstY int) {
	for yy := 0; yy < h; yy++ {
		for xx := 0; xx < w; xx++ {
			si := (yy*w + xx) * 3
			di := ((dstY+yy)*dstW + (dstX + xx)) * 4
			dst[di+0] = src[si+2]
			dst[di+1] = src[si+1]
			dst[di+2] = src[si+0]
			dst[di+3] = 255
		}
	}
}
