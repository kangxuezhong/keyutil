package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/kangxuezhong/gmsm/sm2"
	"github.com/kangxuezhong/gmsm/sm3"
	"github.com/kangxuezhong/gmsm/sm4"
	"github.com/kangxuezhong/gmsm/x509"
	"io"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"strings"
)

func main() {

	//testsm2()
	//fmt.Println()
	//testsm3()
	//fmt.Println()
	//TestSM4()
	//fmt.Println()
	//testRSA()
	//fmt.Println()
	//testMd5()
	//fmt.Println()
	//testAES()
	//return
	//kxz:以下demo没有对err做处理，开发时根据自己具体业务决定
	//demo：SM2密钥生成
	keyPair, _ := genSm2Key()
	fmt.Println("SM2私钥：" + keyPair.priKey)
	fmt.Println("SM2公钥：" + keyPair.pubKey)
	//demo: SM2公钥加密
	data := "浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122"
	ciphertext, _ := sm2Encrypt(keyPair.pubKey, data, 0)
	fmt.Println("SM2加密所得密文：" + ciphertext)
	//demo: SM2私钥解密
	data, _ = sm2Decrypt(keyPair.priKey, ciphertext, 0)
	fmt.Println("SM2解密所得明文：" + data)
	//demo：SM2签名
	sig, _ := sm2Sign(keyPair.priKey, data)
	fmt.Println("SM2签名所得签名：" + sig)
	//demo:SM2验签
	ok, _ := sm2Verify(keyPair.pubKey, data, sig)
	fmt.Println("SM2验签所得结论：" + strconv.FormatBool(ok))
	//demo:SM3哈希
	fmt.Println("SM3哈希运算所得哈希值：" + sm3Hash(data))
	//demo:SM4对称加密
	ciphertexts, _ := sm4CBCEncrypt("1234567890abcdef", data)
	fmt.Println("SM4 CBC模式加密所得密文：" + ciphertexts)
	//demo:SM4对称解密
	data, _ = sm4CBCDecrypt("1234567890abcdef", ciphertexts)
	fmt.Println("SM4 CBC模式解密所得明文：" + data)
}

type KeyPair struct {
	priKey, pubKey string
}

//kxz：不考虑base64、Hex等编码，sm2已知格式私钥有3种，公钥有2种。为与python适配这里指定其中一种
func genSm2Key() (*KeyPair, error) {
	priv, err := sm2.GenerateKey(rand.Reader) // 生成私钥，私钥中包含公钥
	if err != nil {
		return nil, errors.New("SM2密钥生成失败")
	}
	pub := &priv.PublicKey
	keyPair := new(KeyPair)
	keyPair.priKey = x509.WritePrivateKeyToDhex(priv)
	keyPair.pubKey = x509.WritePublicKeyToQhex(pub)
	return keyPair, nil
}

//kxz：与sm2Decrypt配合使用，输入为输出为utf-8编码明文字符串，输出为base64编码密文字符串。加密模式暂定使用0.
func sm2Encrypt(pubKey, plaintext string, cipherMode int) (string, error) {
	if len(pubKey) != 130 || !strings.HasPrefix(pubKey, "04") {
		return "", errors.New("公钥只支持04开头长度为130的Hex字符串")
	}
	var err error
	pub, err := x509.ReadPublicKeyFromQhex(pubKey)
	if err != nil {
		return "", errors.New("公钥加载失败")
	}
	msg := []byte(plaintext)
	var d0 []byte
	if cipherMode == 1 {
		d0, err = sm2.Encrypt(pub, msg, rand.Reader)
	} else {
		d0, err = sm2.EncryptWithOldModel(pub, msg, rand.Reader) //ff
	}

	if err != nil {
		return "", errors.New("SM2公钥加密失败")
	}
	pass64 := base64.StdEncoding.EncodeToString(d0)
	return pass64, nil
}

//kxz：与sm2Encrypt配合使用，输入为base64编码密文字符串，输出为utf-8编码明文字符串。加密模式暂定使用0.
func sm2Decrypt(priKey, ciphertext string, cipherMode int) (string, error) {
	if len(priKey) != 64 {
		return "", errors.New("私钥长度不正确")
	}
	bytesPass, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", nil
	}
	priv := x509.ReadPrivateKeyFromDhex(priKey)
	var d0 []byte
	if cipherMode == 1 {
		d0, err = sm2.Decrypt(priv, bytesPass)
	} else {
		d0, err = sm2.DecryptWithOldModel(priv, bytesPass) //ff
	}
	if err != nil {
		return "", errors.New("解密失败")
	}
	return string(d0), nil
}

//kxz：与sm2Verify配合使用，输入为utf-8编码明文字符串，输出为base64编码签名字符串。
func sm2Sign(priKey, plaintext string) (string, error) {
	if len(priKey) != 64 {
		return "", errors.New("私钥长度不正确")
	}
	priv := x509.ReadPrivateKeyFromDhex(priKey)
	sign, err := priv.Sign(rand.Reader, []byte(plaintext), nil) // 签名
	if err != nil {
		return "", errors.New("签名失败")
	}
	return base64.StdEncoding.EncodeToString(sign), nil
}

//kxz：与sm2Sign配合使用，输入为base64编码签名字符串，输出为验签结果bool。
func sm2Verify(pubKey, plaintext, signature string) (bool, error) {
	if len(pubKey) != 130 || !strings.HasPrefix(pubKey, "04") {
		return false, errors.New("公钥只支持04开头长度为130的Hex字符串")
	}
	pub, err := x509.ReadPublicKeyFromQhex(pubKey)
	if err != nil {
		return false, nil
	}
	bytesPass, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, nil
	}
	ok := pub.Verify([]byte(plaintext), bytesPass) // 密钥验证
	return ok, nil
}

//kxz：输入为utf-8编码明文字符串，输出为base64编码哈希值字符串。
func sm3Hash(plaintext string) string {
	hash1 := sm3.Sm3Sum([]byte(plaintext))
	return base64.StdEncoding.EncodeToString(hash1)
}

//kxz:输入为utf-8编码明文字符串，输出为base64编码密文字符串。
func sm4CBCEncrypt(key, plaintext string) (string, error) {
	block, err := sm4.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	origData := PKCS5Padding([]byte(plaintext), blockSize)

	random := rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.

	iv := make([]byte, blockSize)
	_, err = io.ReadFull(random, iv)
	//iv = make([]byte, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return base64.StdEncoding.EncodeToString(crypted) + ";" + hex.EncodeToString(iv), nil
}

func sm4CBCDecrypt(key, ciphertext string) (string, error) {
	block, err := sm4.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	s := strings.Split(ciphertext, ";")
	iv, _ := hex.DecodeString(s[1])
	//iv = make([]byte, 16)
	blockMode := cipher.NewCBCDecrypter(block, iv)

	bytesPass, err := base64.StdEncoding.DecodeString(s[0])
	origData := make([]byte, len(bytesPass))
	blockMode.CryptBlocks(origData, bytesPass)
	origDatas := PKCS5UnPadding(origData)
	return string(origDatas), nil
}

func testsm2() {
	//密钥生成
	priv, err := sm2.GenerateKey(rand.Reader) // 生成私钥，私钥中包含公钥
	pub := &priv.PublicKey
	fmt.Println(priv.D.Text(16))
	fmt.Println(priv.X.Text(16))
	fmt.Println(priv.Y.Text(16))

	//pem key
	var priOpenSSLPemKey, _ = x509.WritePrivateKeyToOpenSSLPem(priv)
	fmt.Println(string(priOpenSSLPemKey))
	var priPemKey, _ = x509.WritePrivateKeyToPem(priv, nil)
	fmt.Println(string(priPemKey))
	var pubPemKey, _ = x509.WritePublicKeyToPem(pub)
	fmt.Println(string(pubPemKey))
	//hex key
	var priDhex = x509.WritePrivateKeyToDhex(priv)
	fmt.Println(priDhex)
	var pubQhex = x509.WritePublicKeyToQhex(pub)
	fmt.Println(pubQhex)

	//密钥加载
	priv = x509.ReadPrivateKeyFromDhex(priDhex)
	priDhex = x509.WritePrivateKeyToDhex(priv)
	pubQhex = x509.WritePublicKeyToQhex(&priv.PublicKey)
	fmt.Println("Dhex 加载结果：")
	fmt.Println(priDhex)
	fmt.Println(pubQhex)

	priv, _ = x509.ReadPrivateKeyFromOpenSSLPem(priOpenSSLPemKey)
	priDhex = x509.WritePrivateKeyToDhex(priv)
	pubQhex = x509.WritePublicKeyToQhex(&priv.PublicKey)
	fmt.Println("OpenSSLPem 私钥加载结果：")
	fmt.Println(priDhex)
	fmt.Println(pubQhex)

	priv, _ = x509.ReadPrivateKeyFromPem(priPemKey, nil)
	priDhex = x509.WritePrivateKeyToDhex(priv)
	pubQhex = x509.WritePublicKeyToQhex(&priv.PublicKey)
	fmt.Println("P8 Pem 私钥加载结果：")
	fmt.Println(priDhex)
	fmt.Println(pubQhex)

	pub, _ = x509.ReadPublicKeyFromQhex(pubQhex)
	pubQhex = x509.WritePublicKeyToQhex(pub)
	fmt.Println("Qhex 公钥加载结果：")
	fmt.Println(pubQhex)

	pub, _ = x509.ReadPublicKeyFromPem(pubPemKey)
	pubQhex = x509.WritePublicKeyToQhex(pub)
	fmt.Println("x509Pem 公钥加载结果：")
	fmt.Println(pubQhex)

	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线

	//加密
	msg := []byte("浪潮inspur123！@#￥%%……")
	d0, err := sm2.EncryptWithOldModel(pub, msg, rand.Reader) //ff
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	fmt.Printf("Cipher text = %v\n", hex.EncodeToString(d0))

	//解密
	d1, err := sm2.DecryptWithOldModel(priv, d0) //ff
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %s\n", d1)

	//签名
	msg = []byte("123")
	sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		fmt.Printf("Error: failed to sign: %v\n", err)
	}
	fmt.Printf("Signature text = %v\n", hex.EncodeToString(sign))

	//验签
	ok := priv.Verify(msg, sign) // 密钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	pubKey := priv.PublicKey
	ok = pubKey.Verify(msg, sign) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}

	//密钥交换
	ida := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
		'1', '2', '3', '4', '5', '6', '7', '8'}
	idb := []byte{'1', '2', '3', '4', '5', '6', '7', '8',
		'1', '2', '3', '4', '5', '6', '7', '8'}
	daBuf := []byte{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
		0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
		0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
		0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
	dbBuf := []byte{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA,
		0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
		0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
		0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}
	raBuf := []byte{0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
		0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
		0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
		0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3}

	rbBuf := []byte{0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
		0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
		0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
		0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}

	expk := []byte{0x6C, 0x89, 0x34, 0x73, 0x54, 0xDE, 0x24, 0x84,
		0xC6, 0x0B, 0x4A, 0xB1, 0xFD, 0xE4, 0xC6, 0xE5}

	curve := sm2.P256Sm2()
	curve.ScalarBaseMult(daBuf)
	da := new(sm2.PrivateKey)
	da.PublicKey.Curve = curve
	da.D = new(big.Int).SetBytes(daBuf)                          //设置a的固定私钥
	da.PublicKey.X, da.PublicKey.Y = curve.ScalarBaseMult(daBuf) //设置a的固定公钥

	db := new(sm2.PrivateKey)
	db.PublicKey.Curve = curve
	db.D = new(big.Int).SetBytes(dbBuf)                          //设置b的私钥
	db.PublicKey.X, db.PublicKey.Y = curve.ScalarBaseMult(dbBuf) //设置b的固定公钥

	ra := new(sm2.PrivateKey)
	ra.PublicKey.Curve = curve
	ra.D = new(big.Int).SetBytes(raBuf)                          //设置a的临时私钥
	ra.PublicKey.X, ra.PublicKey.Y = curve.ScalarBaseMult(raBuf) //设置a的临时公钥

	rb := new(sm2.PrivateKey)
	rb.PublicKey.Curve = curve
	rb.D = new(big.Int).SetBytes(rbBuf)                          //设置b的临时私钥
	rb.PublicKey.X, rb.PublicKey.Y = curve.ScalarBaseMult(rbBuf) //设置b的临时公钥

	fmt.Println("A的固定私钥：" + da.D.Text(16))
	fmt.Println("A的固定公钥：04" + da.PublicKey.X.Text(16) + da.PublicKey.Y.Text(16))
	fmt.Println("A的临时私钥：" + ra.D.Text(16))
	fmt.Println("A的临时公钥：04" + ra.PublicKey.X.Text(16) + ra.PublicKey.Y.Text(16))

	fmt.Println("B的固定私钥：" + db.D.Text(16))
	fmt.Println("B的固定公钥：04" + db.PublicKey.X.Text(16) + db.PublicKey.Y.Text(16))
	fmt.Println("B的临时私钥：" + rb.D.Text(16))
	fmt.Println("B的临时公钥：04" + rb.PublicKey.X.Text(16) + rb.PublicKey.Y.Text(16))

	k1, Sb, S2, err := sm2.KeyExchangeB(16, ida, idb, db, &da.PublicKey, rb, &ra.PublicKey)
	if err != nil {
		fmt.Printf("Error: failed to key exchange: %v\n", err)
	}
	k2, S1, Sa, err := sm2.KeyExchangeA(16, ida, idb, da, &db.PublicKey, ra, &rb.PublicKey)
	if err != nil {
		fmt.Printf("Error: failed to key exchange: %v\n", err)
	}
	if bytes.Compare(k1, k2) != 0 {
		fmt.Printf("Error: failed to key exchange: %v\n", err)
	}
	if bytes.Compare(k1, expk) != 0 {
		fmt.Printf("Error: failed to key exchange: %v\n", err)
	}
	if bytes.Compare(S1, Sb) != 0 {
		fmt.Printf("Error: failed to key exchange: %v\n", err)
	}
	if bytes.Compare(Sa, S2) != 0 {
		fmt.Printf("Error: failed to key exchange: %v\n", err)
	}

}

func testCompare(key1, key2 []byte) bool {
	if len(key1) != len(key2) {
		return false
	}
	for i, v := range key1 {
		if i == 1 {
			fmt.Println("type of v", reflect.TypeOf(v))
		}
		a := key2[i]
		if a != v {
			return false
		}
	}
	return true
}

func testsm3() {
	msg := []byte("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	//err := ioutil.WriteFile("ifile", msg, os.FileMode(0644)) // 生成测试文件
	//if err != nil {
	//	//t.Fatal(err)
	//}
	//msg, err = ioutil.ReadFile("ifile")
	//if err != nil {
	//	//t.Fatal(err)
	//}
	// 分批次写入
	hw := sm3.New()
	//hw.Write(msg)
	io.WriteString(hw, "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	hash := hw.Sum(nil)
	fmt.Println(hash)
	fmt.Printf("hash = %d\n", len(hash))
	fmt.Printf("%s\n", byteToString(hash))
	fmt.Println(fmt.Sprintf("%x", hash)) //将[]byte转成16进制
	// 一次性写入
	hash1 := sm3.Sm3Sum(msg)
	fmt.Println(hash1)
	fmt.Printf("%s\n", byteToString(hash1))
	fmt.Println(fmt.Sprintf("%x", hash1)) //将[]byte转成16进制
}

func byteToString(b []byte) string {
	ret := ""
	for i := 0; i < len(b); i++ {
		ret += fmt.Sprintf("%02x", b[i])
	}
	return ret
}

func Sm4Encrypt(origData, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	iv := make([]byte, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func Sm4Decrypt(crypted, key []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	iv := make([]byte, blockSize)
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func TestSM4() {
	//初始化密钥、明文
	key := []byte("1234567890abcdef")
	fmt.Printf("key = %v\n", key)
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	data = []byte("浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122")
	//sm4密钥读写
	err := sm4.WriteKeyToPemFile("key.pem", key, nil)
	if err != nil {
		//t.Fatalf("WriteKeyToPem error")
	}
	key, err = sm4.ReadKeyFromPemFile("key.pem", nil)
	fmt.Printf("key = %v\n", key)
	if err != nil {
		//t.Fatal(err)
	}
	//ECB
	fmt.Printf("data = %x\n", data)
	ecbMsg, err := sm4.Sm4Ecb(key, data, true)
	if err != nil {
		//t.Errorf("sm4 enc error:%s", err)
		return
	}
	fmt.Printf("ecbMsg = %x\n", ecbMsg)
	ecbDec, err := sm4.Sm4Ecb(key, ecbMsg, false)
	if err != nil {
		//t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("ecbDec = %x\n", ecbDec)
	if !testCompare(data, ecbDec) {
		//t.Errorf("sm4 self enc and dec failed")
	}
	//CBC
	cbcMsg, err := sm4.Sm4Cbc(key, data, true)
	if err != nil {
		//t.Errorf("sm4 enc error:%s", err)
	}
	fmt.Printf("cbcMsg = %x\n", cbcMsg)
	cbcDec, err := sm4.Sm4Cbc(key, cbcMsg, false)
	if err != nil {
		//t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("cbcDec = %x\n", cbcDec)
	if !testCompare(data, cbcDec) {
		//t.Errorf("sm4 self enc and dec failed")
	}
	//CFB
	cbcMsg, err = sm4.Sm4CFB(key, data, true)
	if err != nil {
		//t.Errorf("sm4 enc error:%s", err)
	}
	fmt.Printf("cbcCFB = %x\n", cbcMsg)
	cbcCfb, err := sm4.Sm4CFB(key, cbcMsg, false)
	if err != nil {
		//t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("cbcCFB = %x\n", cbcCfb)
	//OFB
	cbcMsg, err = sm4.Sm4OFB(key, data, true)
	if err != nil {
		//t.Errorf("sm4 enc error:%s", err)
	}
	fmt.Printf("cbcOFB = %x\n", cbcMsg)
	cbcOfc, err := sm4.Sm4OFB(key, cbcMsg, false)
	if err != nil {
		//t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("cbcOFB = %x\n", cbcOfc)

	xpass, err := Sm4Encrypt(data, key)
	if err != nil {
		fmt.Println(err)
		return
	}

	pass64 := base64.StdEncoding.EncodeToString(xpass)
	fmt.Printf("加密后:%v\n", pass64)

	bytesPass, err := base64.StdEncoding.DecodeString(pass64)
	if err != nil {
		fmt.Println(err)
		return
	}

	tpass, err := Sm4Decrypt(bytesPass, key)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("解密后:%s\n", tpass)
}

func testRSA() {
	GenerateRSAKey(2048)
	message := []byte("hello world")
	//加密
	cipherText := RSA_Encrypt(message, "public.pem")
	fmt.Println("加密后为：", string(cipherText))
	//解密
	plainText := RSA_Decrypt(cipherText, "private.pem")
	fmt.Println("解密后为：", string(plainText))

}

//生成RSA私钥和公钥，保存到文件中
func GenerateRSAKey(bits int) {
	//GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	//Reader是一个全局、共享的密码用强随机数生成器
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	//保存私钥
	//通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	println(base64.RawStdEncoding.EncodeToString(X509PrivateKey))
	//使用pem格式对x509输出的内容进行编码
	//创建文件保存私钥
	privateFile, err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	defer privateFile.Close()
	//构建一个pem.Block结构体对象
	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}
	//将数据保存到文件
	pem.Encode(privateFile, &privateBlock)

	//保存公钥
	//获取公钥的数据
	publicKey := privateKey.PublicKey
	//X509对公钥编码
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	//pem格式编码
	//创建用于保存公钥的文件
	publicFile, err := os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	defer publicFile.Close()
	//创建一个pem.Block结构体对象
	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}
	//保存到文件
	pem.Encode(publicFile, &publicBlock)
}

//RSA加密
func RSA_Encrypt(plainText []byte, path string) []byte {
	//打开文件
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	//读取文件的内容
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//x509解码

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//类型断言
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	//对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		panic(err)
	}
	//返回密文
	return cipherText
}

//RSA解密
func RSA_Decrypt(cipherText []byte, path string) []byte {
	//打开文件
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	//获取文件内容
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//X509解码
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//对密文进行解密
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	//返回明文
	return plainText
}

func testMd5() {
	str := "123456"
	//方法一
	data := []byte(str)
	has := md5.Sum(data)
	md5str1 := fmt.Sprintf("%x", has) //将[]byte转成16进制
	fmt.Println(md5str1)
	//方法二
	w := md5.New()
	io.WriteString(w, str)
	//将str写入到w中
	md5str2 := fmt.Sprintf("%x", w.Sum(nil))

	fmt.Println(md5str2)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	origData1 := origData[:128]
	origData2 := origData[128:]
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	crypted1 := make([]byte, 128)
	crypted2 := make([]byte, 128)
	//blockMode.CryptBlocks(crypted, origData)
	blockMode.CryptBlocks(crypted1, origData1)
	blockMode.CryptBlocks(crypted2, origData2)
	crypted = append(crypted1, crypted2...)

	return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func testAES() {
	var aeskey = []byte("321423u9y8d2fwfl")
	pass := []byte("浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122浪潮inspur！@#￥%……122")
	xpass, err := AesEncrypt(pass, aeskey)
	if err != nil {
		fmt.Println(err)
		return
	}

	pass64 := base64.StdEncoding.EncodeToString(xpass)
	fmt.Printf("加密后:%v\n", pass64)

	bytesPass, err := base64.StdEncoding.DecodeString(pass64)
	if err != nil {
		fmt.Println(err)
		return
	}

	tpass, err := AesDecrypt(bytesPass, aeskey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("解密后:%s\n", tpass)

}
