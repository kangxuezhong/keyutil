package keyutil

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/kangxuezhong/gmsm/sm4"
	"io"
	"strings"
)

func GenSM4Key() (string, error) {
	random := rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	key := make([]byte, sm4.BlockSize)
	if _, err1 := io.ReadFull(random, key); err1 != nil {
		return "", err1
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

//kxz:输入为utf-8编码明文字符串，输出为base64编码密文字符串。
func Sm4CBCEncrypt(key, plaintext string) (string, error) {
	if !notEmptyCheck(key) {
		return "", errors.New(sm4KeyStrSupport)
	}
	if !notEmptyCheck(plaintext) {
		return "", errors.New(plaintextSupport)
	}

	keyArray, err1 := base64.StdEncoding.DecodeString(key)
	if err1 != nil {
		return "", err1
	}
	if !sm4KeyCheck(keyArray) {
		return "", errors.New(sm4KeyArraySupport)
	}

	block, err2 := sm4.NewCipher(keyArray)
	if err2 != nil {
		return "", err2
	}

	origData := pkcs7Padding([]byte(plaintext), sm4.BlockSize)
	random := rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	iv := make([]byte, sm4.BlockSize)
	if _, err3 := io.ReadFull(random, iv); err3 != nil {
		return "", err3
	}

	encryptedData := make([]byte, len(origData))

	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(encryptedData, origData)

	return base64.StdEncoding.EncodeToString(encryptedData) + ";" + hex.EncodeToString(iv), nil
}

//kxz:输入为base64编码密文字符串，输出为utf-8编码明文字符串。
func Sm4CBCDecrypt(key, ciphertext string) (string, error) {
	if !notEmptyCheck(key) {
		return "", errors.New(sm4KeyStrSupport)
	}
	if !notEmptyCheck(ciphertext) {
		return "", errors.New(ciphertextSupport)
	}

	keyArray, err1 := base64.StdEncoding.DecodeString(key)
	if err1 != nil {
		return "", err1
	}
	if !sm4KeyCheck(keyArray) {
		return "", errors.New(sm4KeyArraySupport)
	}

	block, err2 := sm4.NewCipher(keyArray)
	if err2 != nil {
		return "", err2
	}

	s := strings.Split(ciphertext, ";")
	bytesPass, err3 := base64.StdEncoding.DecodeString(s[0])
	if err3 != nil {
		return "", err3
	}
	iv, err4 := hex.DecodeString(s[1])
	if err4 != nil {
		return "", err4
	}

	origData := make([]byte, len(bytesPass))

	blockMode := cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(origData, bytesPass)

	return string(pkcs7UnPadding(origData)), nil
}
