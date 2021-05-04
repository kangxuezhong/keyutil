package keyutil

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/kangxuezhong/gmsm/sm2"
	"github.com/kangxuezhong/gmsm/x509"
)

type KeyPair struct {
	priKey, pubKey string
}

//kxz：不考虑base64、Hex等编码，sm2已知格式私钥有3种，公钥有2种。这里指定其中一种
func GenSm2Key() (*KeyPair, error) {
	pri, err := sm2.GenerateKey(rand.Reader) // 生成私钥，私钥中包含公钥
	if err != nil {
		return nil, err
	}
	pub := &pri.PublicKey
	keyPair := new(KeyPair)
	keyPair.priKey = x509.WritePrivateKeyToDhex(pri)
	keyPair.pubKey = x509.WritePublicKeyToQhex(pub)
	return keyPair, nil
}

//kxz：sm2公钥加密，与sm2Decrypt配合使用，输入为输出为utf-8编码明文字符串。输出为base64编码密文字符串。加密模式暂定使用0.
func Sm2Encrypt(pubKey, plaintext string, cipherMode int) (string, error) {
	if !sm2PubKeyCheck(pubKey) {
		return "", errors.New(sm2PubKeySupport)
	}
	if !notEmptyCheck(plaintext) {
		return "", errors.New(plaintextSupport)
	}

	pub, err1 := x509.ReadPublicKeyFromQhex(pubKey)
	if err1 != nil {
		return "", err1
	}

	msg := []byte(plaintext)
	var d0 []byte
	var err2 error
	if cipherMode == 1 {
		d0, err2 = sm2.Encrypt(pub, msg, rand.Reader)
	} else {
		d0, err2 = sm2.EncryptWithOldModel(pub, msg, rand.Reader)
	}
	if err2 != nil {
		return "", err2
	}

	return base64.StdEncoding.EncodeToString(d0), nil
}

//kxz：sm2私钥解密，与sm2Encrypt配合使用，输入为base64编码密文字符串，输出为utf-8编码明文字符串。加密模式暂定使用0.
func Sm2Decrypt(priKey, ciphertext string, cipherMode int) (string, error) {
	if !sm2PriKeyCheck(priKey) {
		return "", errors.New(sm2PriKeySupport)
	}
	if !notEmptyCheck(ciphertext) {
		return "", errors.New(ciphertextSupport)
	}

	bytesPass, err1 := base64.StdEncoding.DecodeString(ciphertext)
	if err1 != nil {
		return "", err1
	}
	if !sm2CiphertextCheck(bytesPass) {
		return "", errors.New(sm2CiphertextSupport)
	}

	priv := x509.ReadPrivateKeyFromDhex(priKey)
	var d0 []byte
	var err2 error
	if cipherMode == 1 {
		d0, err2 = sm2.Decrypt(priv, bytesPass)
	} else {
		d0, err2 = sm2.DecryptWithOldModel(priv, bytesPass)
	}
	if err2 != nil {
		return "", err2
	}

	return string(d0), nil
}

//kxz：与sm2VerifyWithSM3配合使用，输入为utf-8编码明文字符串，输出为base64编码签名字符串。
func Sm2SignWithSM3(priKey, plaintext string) (string, error) {
	if !sm2PriKeyCheck(priKey) {
		return "", errors.New(sm2PriKeySupport)
	}
	if !notEmptyCheck(plaintext) {
		return "", errors.New(plaintextSupport)
	}

	priv := x509.ReadPrivateKeyFromDhex(priKey)
	sign, err1 := priv.Sign(rand.Reader, []byte(plaintext), nil) // 签名
	if err1 != nil {
		return "", err1
	}

	return base64.StdEncoding.EncodeToString(sign), nil
}

//kxz：与sm2SignWithSM3配合使用，输入为base64编码签名字符串，输出为验签结果bool。
func Sm2VerifyWithSM3(pubKey, plaintext, signature string) (bool, error) {
	if !sm2PubKeyCheck(pubKey) {
		return false, errors.New(sm2PubKeySupport)
	}
	if !notEmptyCheck(plaintext) {
		return false, errors.New(plaintextSupport)
	}
	if !notEmptyCheck(signature) {
		return false, errors.New(signatureSupport)
	}

	pub, err1 := x509.ReadPublicKeyFromQhex(pubKey)
	if err1 != nil {
		return false, err1
	}

	bytesPass, err2 := base64.StdEncoding.DecodeString(signature)
	if err2 != nil {
		return false, err2
	}
	if !sm2SignatureCheck(bytesPass) {
		return false, errors.New(sm2SignatureSupport)
	}

	return pub.Verify([]byte(plaintext), bytesPass), nil
}
