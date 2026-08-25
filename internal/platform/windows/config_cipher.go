package windows

import (
	"encoding/hex"
	"errors"
	"math"
	"runtime"
)

type ConfigMemoryReader interface {
	ReadMemory(address uint64, size int) ([]byte, error)
}

type SensitiveRuntime struct {
	CloneSensitive func([]byte) []byte
	MarkSensitive  func([]byte)
	ClearSensitive func([]byte)
}

func (sensitive SensitiveRuntime) clone(value []byte) []byte {
	if sensitive.CloneSensitive != nil {
		return sensitive.CloneSensitive(value)
	}
	return append([]byte(nil), value...)
}

func (sensitive SensitiveRuntime) mark(value []byte) {
	if len(value) > 0 && sensitive.MarkSensitive != nil {
		sensitive.MarkSensitive(value)
	}
}

func (sensitive SensitiveRuntime) clear(value []byte) {
	if len(value) == 0 {
		return
	}
	if sensitive.ClearSensitive != nil {
		sensitive.ClearSensitive(value)
		return
	}
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func AddConfigOffset(address uint64, offset int64) (uint64, bool) {
	if offset >= 0 {
		addition := uint64(offset)
		if address > math.MaxUint64-addition {
			return 0, false
		}
		return address + addition, true
	}
	subtraction := uint64(-(offset + 1)) + 1
	if subtraction > address {
		return 0, false
	}
	return address - subtraction, true
}

func DecodeConfigCipherCandidate(encoded []byte, recipe ConfigCipherRecipe, sensitive SensitiveRuntime) ([]byte, error) {
	if !recipe.Valid() || len(encoded) != recipe.EncodedLength {
		return nil, errors.New("invalid Config.Cipher candidate layout")
	}
	decoded := append([]byte(nil), encoded...)
	defer sensitive.clear(decoded)
	if len(recipe.XORMask) > 0 {
		for index := range decoded {
			decoded[index] ^= recipe.XORMask[index%len(recipe.XORMask)]
		}
	}
	switch recipe.CandidateEncoding {
	case "raw32":
		if len(decoded) != 32 {
			return nil, errors.New("invalid raw Config.Cipher length")
		}
		return sensitive.clone(decoded), nil
	case "hex64":
		value := make([]byte, 32)
		if _, err := hex.Decode(value, decoded); err != nil {
			sensitive.clear(value)
			return nil, errors.New("invalid hexadecimal Config.Cipher candidate")
		}
		sensitive.mark(value)
		return value, nil
	default:
		return nil, errors.New("unsupported Config.Cipher encoding")
	}
}

func ExtractConfigCipherCandidate(reader ConfigMemoryReader, needleAddress uint64, pointerSize int, recipe ConfigCipherRecipe, sensitive SensitiveRuntime) ([]byte, error) {
	if reader == nil || !recipe.Valid() || (pointerSize != 4 && pointerSize != 8) {
		return nil, errors.New("invalid Config.Cipher extraction request")
	}
	current := needleAddress
	for _, offset := range recipe.PointerOffsets {
		pointerAddress, ok := AddConfigOffset(current, offset)
		if !ok {
			return nil, errors.New("Config.Cipher pointer arithmetic overflow")
		}
		value, err := reader.ReadMemory(pointerAddress, pointerSize)
		defer sensitive.clear(value)
		if err != nil || len(value) != pointerSize {
			return nil, errors.New("Config.Cipher pointer read failed")
		}
		if pointerSize == 4 {
			current = uint64(value[0]) | uint64(value[1])<<8 | uint64(value[2])<<16 | uint64(value[3])<<24
		} else {
			current = uint64(value[0]) | uint64(value[1])<<8 | uint64(value[2])<<16 | uint64(value[3])<<24 |
				uint64(value[4])<<32 | uint64(value[5])<<40 | uint64(value[6])<<48 | uint64(value[7])<<56
		}
		if current < 0x10000 {
			return nil, errors.New("Config.Cipher pointer is outside the user address range")
		}
	}
	dataAddress, ok := AddConfigOffset(current, recipe.DataOffset)
	if !ok {
		return nil, errors.New("Config.Cipher data arithmetic overflow")
	}
	encoded, err := reader.ReadMemory(dataAddress, recipe.EncodedLength)
	defer sensitive.clear(encoded)
	if err != nil || len(encoded) != recipe.EncodedLength {
		return nil, errors.New("Config.Cipher candidate read failed")
	}
	return DecodeConfigCipherCandidate(encoded, recipe, sensitive)
}
