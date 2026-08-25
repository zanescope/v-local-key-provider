package windows

import (
	"encoding/binary"
	"errors"
	"testing"
)

type configMemory map[uint64][]byte

func (memory configMemory) ReadMemory(address uint64, size int) ([]byte, error) {
	value, found := memory[address]
	if !found || len(value) != size {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), value...), nil
}

func TestExtractConfigCipherCandidateFollowsBoundedPointerRecipe(t *testing.T) {
	recipe := ConfigCipherRecipe{
		Needle: []byte("needle"), PointerOffsets: []int64{8}, DataOffset: 16,
		EncodedLength: 32, CandidateEncoding: "raw32", CandidateKind: "raw_enc_key", MaxMatches: 1,
	}
	pointer := make([]byte, 8)
	binary.LittleEndian.PutUint64(pointer, 0x200000)
	want := make([]byte, 32)
	for index := range want {
		want[index] = byte(index + 1)
	}
	actual, err := ExtractConfigCipherCandidate(configMemory{
		0x100008: pointer,
		0x200010: want,
	}, 0x100000, 8, recipe, SensitiveRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(want) {
		t.Fatalf("unexpected candidate size: %d", len(actual))
	}
	for index := range want {
		if actual[index] != want[index] {
			t.Fatalf("candidate mismatch at %d", index)
		}
	}
}

func TestConfigCipherPointerArithmeticFailsClosed(t *testing.T) {
	if _, ok := AddConfigOffset(^uint64(0)-3, 8); ok {
		t.Fatal("positive pointer overflow was accepted")
	}
	if _, ok := AddConfigOffset(3, -8); ok {
		t.Fatal("negative pointer underflow was accepted")
	}
}
