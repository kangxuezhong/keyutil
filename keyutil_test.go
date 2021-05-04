package keyutil

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"
)

var data = "浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123"

func TestSm2(t *testing.T) {
	//SM2密钥生成
	keyPair, err1 := GenSm2Key()
	if err1 != nil {
		t.Fatal(err1)
	}
	t.Log("SM2私钥：" + keyPair.priKey)
	t.Log("SM2公钥：" + keyPair.pubKey)

	//SM2公钥加密
	ciphertext, err2 := Sm2Encrypt(keyPair.pubKey, data, 0)
	if err2 != nil {
		t.Fatal(err2)
	}
	t.Log("SM2加密所得密文：" + ciphertext)

	//SM2私钥解密
	dataDecrypted, err3 := Sm2Decrypt(keyPair.priKey, ciphertext, 0)
	if err3 != nil {
		t.Fatal(err3)
	}
	t.Log("SM2解密所得明文：" + dataDecrypted)
	if dataDecrypted != data {
		t.Fail()
	}

	//SM2签名
	sig, err4 := Sm2SignWithSM3(keyPair.priKey, data)
	if err4 != nil {
		t.Fatal(err4)
	}
	t.Log("SM2签名所得签名：" + sig)

	//SM2验签
	ok, err5 := Sm2VerifyWithSM3(keyPair.pubKey, data, sig)
	if err5 != nil {
		t.Fatal(err5)
	}
	t.Log("SM2验签所得结论：" + strconv.FormatBool(ok))
	if !ok {
		t.Fail()
	}
}

func TestSm3(t *testing.T) {
	//SM3哈希
	hash, err1 := Sm3Hash(data)
	if err1 != nil {
		t.Fatal(err1)
	}
	t.Log("SM3哈希运算所得哈希值：" + hash)
	expectedHashArray, _ := hex.DecodeString("20d91a064c4a321f758e100a303efec8def1d4c4d4475b0c00a528fa9880fbdf")
	if hash != base64.StdEncoding.EncodeToString(expectedHashArray) {
		t.Fail()
	}
}

func TestSM4(t *testing.T) {
	//SM4密钥生成
	key, err1 := GenSM4Key()
	if err1 != nil {
		t.Fatal(err1)
	}
	t.Log("SM4密钥：" + key)

	//SM4对称加密
	ciphertexts, err2 := Sm4CBCEncrypt(key, data)
	if err2 != nil {
		t.Fatal(err2)
	}
	t.Log("SM4 CBC模式加密所得密文：" + ciphertexts)

	//SM4对称解密
	dataDecrypted, err3 := Sm4CBCDecrypt(key, ciphertexts)
	if err3 != nil {
		t.Fatal(err3)
	}
	t.Log("SM4 CBC模式解密所得明文：" + dataDecrypted)
	if data != dataDecrypted {
		t.Fail()
	}
}
