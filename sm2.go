package keyutil

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"io"
	"math/big"
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
	keyPair.priKey = writePrivateKeyToHex(pri)
	keyPair.pubKey = writePublicKeyToHex(pub)
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

	pub, err1 := readPublicKeyFromHex(pubKey)
	if err1 != nil {
		return "", err1
	}

	msg := []byte(plaintext)
	var d0 []byte
	var err2 error
	if cipherMode == 1 {
		d0, err2 = sm2.Encrypt(pub, msg, rand.Reader)
	} else {
		d0, err2 = encryptWithOldModel(pub, msg, rand.Reader)
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

	priv, err3 := readPrivateKeyFromHex(priKey)
	if err3 != nil {
		return "", err3
	}
	var d0 []byte
	var err2 error
	if cipherMode == 1 {
		d0, err2 = sm2.Decrypt(priv, bytesPass)
	} else {
		d0, err2 = decryptWithOldModel(priv, bytesPass)
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

	priv, err2 := readPrivateKeyFromHex(priKey)
	if err2 != nil {
		return "", err2
	}
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

	pub, err1 := readPublicKeyFromHex(pubKey)
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

//kxz：该函数已并入主线，为先固定版本手动copy至此，等gmsm包更新发版后可使用最新版并删除此函数。
func writePrivateKeyToHex(key *sm2.PrivateKey) string {
	return key.D.Text(16)
}

//kxz：该函数已并入主线，为先固定版本手动copy至此，等gmsm包更新发版后可使用最新版并删除此函数。
func writePublicKeyToHex(key *sm2.PublicKey) string {
	x := key.X.Bytes()
	y := key.Y.Bytes()
	if n := len(x); n < 32 {
		x = append(zeroByteSlice()[:32-n], x...)
	}
	if n := len(y); n < 32 {
		y = append(zeroByteSlice()[:32-n], y...)
	}
	c := []byte{}
	c = append(c, x...)
	c = append(c, y...)
	c = append([]byte{0x04}, c...)
	return hex.EncodeToString(c)
}

// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

//kxz：该函数已并入主线，为先固定版本手动copy至此，等gmsm包更新发版后可使用最新版并删除此函数。
func readPublicKeyFromHex(Qhex string) (*sm2.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 65 && q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 64 {
		return nil, errors.New("publicKey is not uncompressed.")
	}
	pub := new(sm2.PublicKey)
	pub.Curve = sm2.P256Sm2()
	pub.X = new(big.Int).SetBytes(q[:32])
	pub.Y = new(big.Int).SetBytes(q[32:])
	return pub, nil
}

//kxz：该函数已并入主线，为先固定版本手动copy至此，等gmsm包更新发版后可使用最新版并删除此函数。
func readPrivateKeyFromHex(Dhex string) (*sm2.PrivateKey, error) {
	c := sm2.P256Sm2()
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func encryptWithOldModel(pub *sm2.PublicKey, data []byte, random io.Reader) ([]byte, error) {
	ciphertext, err := sm2.Encrypt(pub, data, random)
	if err != nil {
		return ciphertext, err
	}
	ciphertext = ciphertext[1:]
	c1 := make([]byte, 64)
	c2 := make([]byte, len(ciphertext)-96)
	c3 := make([]byte, 32)
	copy(c1, ciphertext[:64])   //x1,y1
	copy(c3, ciphertext[64:96]) //hash
	copy(c2, ciphertext[96:])   //密文
	c := []byte{}
	c = append(c, c1...)
	c = append(c, c2...)
	c = append(c, c3...)

	return append([]byte{0x04}, c...), nil
}

func decryptWithOldModel(priv *sm2.PrivateKey, data []byte) ([]byte, error) {
	data = data[1:]
	c1 := make([]byte, 64)
	c2 := make([]byte, len(data)-96)
	c3 := make([]byte, 32)

	copy(c1, data[:64])             //x1,y1
	copy(c2, data[64:len(data)-32]) //密文
	copy(c3, data[len(data)-32:])   //hash
	c := []byte{}
	c = append(c, c1...)
	c = append(c, c3...)
	c = append(c, c2...)
	data = append([]byte{0x04}, c...)
	return sm2.Decrypt(priv, data)
}
