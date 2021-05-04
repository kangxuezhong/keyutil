package keyutil

import (
	"encoding/base64"
	"errors"
	"github.com/kangxuezhong/gmsm/sm3"
)

//kxz：输入为utf-8编码明文字符串，输出为base64编码哈希值字符串。
func Sm3Hash(plaintext string) (string, error) {
	if !notEmptyCheck(plaintext) {
		return "", errors.New(plaintextSupport)
	}

	hash := sm3.Sm3Sum([]byte(plaintext))
	return base64.StdEncoding.EncodeToString(hash), nil
}
