package keyutil

import (
	"bytes"
	"strings"
)

func hexCheck(str string) bool {
	dat := []byte(str)
	for _, v := range dat {
		if v >= 48 && v <= 57 || v >= 65 && v <= 70 || v >= 97 && v <= 102 {
			return true
		} else {
			return false
		}
	}
	return false
}

var plaintextSupport string = "明文长度不得为0"
var ciphertextSupport string = "密文长度不得为0"
var signatureSupport string = "签名长度不得为0"
var sm4KeyStrSupport string = "sm4密钥长度不得为0"

func notEmptyCheck(str string) bool {
	return len(str) != 0
}

var sm2PriKeySupport string = "sm2私钥只支持长度为64的Hex字符串"

func sm2PriKeyCheck(priKeyStr string) bool {
	if len(priKeyStr) != 64 {
		return false
	}
	if !hexCheck(priKeyStr) {
		return false
	}
	return true
}

var sm2PubKeySupport string = "sm2公钥只支持04开头且长度为130的Hex字符串"

func sm2PubKeyCheck(pubKeyStr string) bool {
	if len(pubKeyStr) != 130 {
		return false
	}
	if !strings.HasPrefix(pubKeyStr, "04") {
		return false
	}
	if !hexCheck(pubKeyStr) {
		return false
	}
	return true
}

var sm2CiphertextSupport string = "sm2密文只支持0x04开头且长度大于97的byte数组"

func sm2CiphertextCheck(ciphertextArray []byte) bool {
	if len(ciphertextArray) <= 1+64+32 {
		return false
	}
	if ciphertextArray[0] != 0x04 {
		return false
	}
	return true
}

var sm2SignatureSupport string = "sm2签名只支持0x30开头的byte数组"

func sm2SignatureCheck(sigArray []byte) bool {
	if sigArray[0] != 0x30 {
		return false
	}
	return true
}

var sm4KeyArraySupport string = "sm4只支持长度为16的byte数组"

func sm4KeyCheck(sm4KeyArray []byte) bool {
	if len(sm4KeyArray) != 16 {
		return false
	}
	return true
}

func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
