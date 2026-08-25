package acquisition

import "crypto/aes"

func isHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func validImageHeader(plain []byte) bool {
	return len(plain) >= 4 && (plain[0] == 0xff && plain[1] == 0xd8 && plain[2] == 0xff ||
		string(plain[:4]) == "\x89PNG" || string(plain[:4]) == "wxgf" ||
		string(plain[:3]) == "GIF" || string(plain[:4]) == "RIFF")
}

func validateMediaAESBlocks(blocks [][16]byte, candidate string) bool {
	if len(blocks) == 0 || len(candidate) != 16 {
		return false
	}
	cipher, err := aes.NewCipher([]byte(candidate))
	if err != nil {
		return false
	}
	plain := make([]byte, aes.BlockSize)
	for _, encrypted := range blocks {
		cipher.Decrypt(plain, encrypted[:])
		if !validImageHeader(plain) {
			return false
		}
	}
	return true
}

func (collector *Collector) validateMediaAES(candidate string) bool {
	return validateMediaAESBlocks(collector.mediaBlocks, candidate)
}
