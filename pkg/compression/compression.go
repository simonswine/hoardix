package compression

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

type Type byte

const (
	TypeNone = iota
	TypeXZ
)

func IsXZ(data []byte) error {
	var (
		headerLen   = 12
		headerMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}
	)

	// header length
	if len(data) < headerLen {
		return errors.New("xz: wrong file header length")
	}

	data = data[:headerLen]

	// magic header
	if !bytes.Equal(headerMagic, data[:6]) {
		return errors.New("xz: wrong header magic")
	}

	// checksum
	crc := crc32.NewIEEE()
	crc.Write(data[6:8])
	if exp, act := binary.LittleEndian.Uint32(data[8:]), crc.Sum32(); exp != act {
		return fmt.Errorf("xz: invalid checksum for file header expected %x got %x", exp, act)
	}

	return nil
}
