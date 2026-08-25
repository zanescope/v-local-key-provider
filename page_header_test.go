package provider

import "testing"

// buildSQLCipherFirstPageBody 组装一个满足 validSQLitePageHeader 校验的首页正文，
// pageSizeField 直接写入头部的页大小字段（SQLite 约定：值 1 表示 64 KiB）。
func buildSQLCipherFirstPageBody(pageSizeHigh, pageSizeLow byte, reserve int) []byte {
	body := make([]byte, 24)
	body[0], body[1] = pageSizeHigh, pageSizeLow
	body[4] = byte(reserve)
	body[5], body[6], body[7] = 64, 32, 32
	return body
}

func TestValidSQLitePageHeaderAcceptsStandardPageSizes(t *testing.T) {
	// 头部字段值 -> 期望页大小。1 是 SQLite 对 64 KiB 的特殊编码。
	cases := map[[2]byte]int{
		{0x02, 0x00}: 512,
		{0x10, 0x00}: 4096,
		{0x80, 0x00}: 32768,
		{0x00, 0x01}: 65536, // 编码值 1
	}
	for field, size := range cases {
		body := buildSQLCipherFirstPageBody(field[0], field[1], 80)
		if !validSQLitePageHeader(body, 80, 16) {
			t.Errorf("页大小 %d（字段 %v）应通过校验", size, field)
		}
	}
}

// 回归 S-04：64 KiB 页（编码值 1）此前因 pageSize == 65536 分支不可达而被误判为无效。
func TestValidSQLitePageHeaderAccepts64KiBEncodedAsOne(t *testing.T) {
	body := buildSQLCipherFirstPageBody(0x00, 0x01, 80)
	if !validSQLitePageHeader(body, 80, 16) {
		t.Fatal("编码为 1 的 64 KiB 页被误判为无效（S-04 回归）")
	}
}

func TestValidSQLitePageHeaderRejectsNonPowerOfTwo(t *testing.T) {
	// 4095 不是 2 的幂，必须拒绝。
	body := buildSQLCipherFirstPageBody(0x0f, 0xff, 80)
	if validSQLitePageHeader(body, 80, 16) {
		t.Fatal("非 2 的幂页大小不应通过")
	}
}

func TestValidSQLitePageHeaderRejectsWrongReserve(t *testing.T) {
	body := buildSQLCipherFirstPageBody(0x10, 0x00, 80)
	if validSQLitePageHeader(body, 48, 16) {
		t.Fatal("reserve 不匹配时不应通过")
	}
}

func TestProfileHeaderValidationRejectsDifferentPageSize(t *testing.T) {
	body := buildSQLCipherFirstPageBody(0x20, 0x00, 80)
	if validSQLitePageHeaderForPageSize(body, 4096, 80, 16) {
		t.Fatal("与 profile 不一致的页大小不应通过")
	}
}
