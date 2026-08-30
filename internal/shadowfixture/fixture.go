package shadowfixture

const (
	SyntheticBuildDigest  = "6170b8b73eb596f4a22aed6f4c15a9fb92900f3924152b0fc174b11122930bf9"
	SyntheticSourceDigest = "6d221ae3f44995df0b2c09a124859ad11908bcd0ee0630fc9efe15ce1c12ee1e"
)

func Credential() []byte {
	return []byte(`{"image_keys":{"aes":"1234567890abcdef","xor":7}}`)
}
