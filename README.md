# keyutil
本demo基于苏州同济区块链研究院有限公司的[gmsm](https://github.com/tjfoc/gmsm) ，gmsm代码风格和crypto标准库基本相同。但其sm2不支持Hex格式密钥和C1C2C3旧加密模式，笔者已实现并推送至gmsm，但gmsm还未接受。所以暂时需要从<https://github.com/kangxuezhong/gmsm>下载主线代码并在go.mod中做如下处理：
```
require (
	github.com/kangxuezhong/gmsm v1.4.1
	github.com/tjfoc/gmsm v1.4.0 // indirect
)

replace github.com/kangxuezhong/gmsm => ../gmsm
```

另外，密钥的格式以及密文签名的编码是个复杂而又无聊的东西。为简单起见，这里直接指定某种通用格式。所以，若是与其它语言或第三方工具进行交互可能需要对密钥、密文、签名、偏移向量等做下格式转换。
```go
//本demo的加密对象是utf-8编码的短字符串，大数据比如1G的文件不适用本demo（一次性加载对内存负担太大，需要分块处理）
var data = "浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123"
```

## sm2
```go
keyPair, err1 := GenSm2Key()
fmt.Println("SM2私钥：" + keyPair.priKey)//SM2私钥：52f0f5ef85ad5bbf7be1ab29db390dd7a989011ee7b50f2eb33a1c9aa6e67411
fmt.Println("SM2公钥：" + keyPair.pubKey)//SM2公钥：04ee1380c20d718a347b4403299123c8eb91813bb7faae541f372e93a83226091f3740c83d43a7728c87b4f1d7b32bf00fa81fae39fd2de647b2f72e5462d1612e

//SM2公钥加密
ciphertext, err2 := Sm2Encrypt(keyPair.pubKey, data, 0)
fmt.Println("SM2加密所得密文：" + ciphertext)//SM2加密所得密文：BOD2lWAYDxbb7YfY0Hdc0lx1x/Ot8wpuIUPQ3D7eGnFXE1DhFRwbDXYakBDdJq4k0qpf3CJbIOb+UtVHgof/r/VUODirfvtdTFg/bz5F6QECixdNRa0vpKAJ6KhlBfOps5fXStQINLaU34fzqlRvt7yi2TJ9RAkNY8FdF194Otqno06HqtwdZ83RWyDjOAfX1+MlMyZgvq7GDk9YZha43/LgkSw2lw4k7YPTmhmoopv+pVyYJVhC/JcGfN0gowdjIg3Vls2YI4jtwvS8nndBbIjEofz4rL/8k51M1VfJJslBiDbqutqAS1ZjpQuh3LOx2sKth/WPnrSpCu6+I8CjP50TfdMtQAtbFZ5wfVrRQafUheA3auhnk8CdhwdgRC3CjDm9h7amkiR+n2sjmztEJe0bWStQca4fLaakHex7AUJUL8uKlLZfGFQWDJsXnyLodjp1BEU1+7zrJfJt4DpCUMnpfLsiNgpUIZySYklqPNVakJmUWZbDPEQGV00L5tmm0wNO6WUoBw==

//SM2私钥解密
dataDecrypted, err3 := Sm2Decrypt(keyPair.priKey, ciphertext, 0)
fmt.Println("SM2解密所得明文：" + dataDecrypted)//SM2解密所得明文：浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123

//SM2签名
sig, err4 := Sm2SignWithSM3(keyPair.priKey, data)
fmt.Println("SM2签名所得签名：" + sig)//SM2签名所得签名：MEYCIQDvva5BuXNQaYb66GWEzu9eJnnVIEVsjr1m9V4uJmYf7QIhAPSH4kSB92k01CV+xs2qE8PKKs9p/aipZeH/o+7xrptB

//SM2验签
ok, err5 := Sm2VerifyWithSM3(keyPair.pubKey, data, sig)
fmt.Println("SM2验签所得结论：" + strconv.FormatBool(ok))//SM2验签所得结论：true
```

## sm3
```go
//SM3哈希
hash, err1 := Sm3Hash(data)
fmt.Println("SM3哈希运算所得哈希值：" + hash)//SM3哈希运算所得哈希值：INkaBkxKMh91jhAKMD7+yN7x1MTUR1sMAKUo+piA+98=
```
注意：这里仅仅是对短字符串进行哈希运算，对超长字符串甚至文件进行哈希计算不可以使用该方式。若有需求请联系作者或自行研究。

## sm4
```go
//SM4密钥生成
key, err1 := GenSM4Key()
fmt.Println("SM4密钥：" + key)//SM4密钥：TR36VNZFyQBmk98J1Z7RSA==

//SM4对称加密
ciphertexts, err2 := Sm4CBCEncrypt(key, data)
fmt.Println("SM4 CBC模式加密所得密文：" + ciphertexts)//SM4 CBC模式加密所得密文：IposvripxP/nOwdfOqnyYVr2AVxYyuJIpccqk/+PdzDh35T7Q2Q9kvcQTbAQHYsa1BMGm/zsN45PAKqZK2fAuiI7mJ5hoJQ4L/DaJfZqYBOrwn7xyWBrntJzGPXUjnBd7uahH1JmA2ZXAu9+rb2RoEXp7gVetKrZ1QFnV2i7z2w9uqjUSdC0jCm22MhBMgxGK+F4M91in6KFMhVOzWqgVqzZWOB8TX+Pn55thZKiGeqRd89iywuSX4Qtrevpi/MZ0KchAAeRKPCSHAFsvoQ7dqBICSzSWEcl5VlaGmTfsG9QH1mAFFl0K0LWIWMywhbLzOgDLn4Fn6CCijjYofTBibp13JgJmjEEL4QJ/iuzUUSWAc2x4UtT42cOxWR03pZHhj6gFE34M/pFMIiM0MjwDw==;6e1c6438560225340720fe0dbfd83b9a

//SM4对称解密
dataDecrypted, err3 := Sm4CBCDecrypt(key, ciphertexts)
fmt.Println("SM4 CBC模式解密所得明文：" + dataDecrypted)//SM4 CBC模式解密所得明文：浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123浪潮inspur！@#￥%……&*（）—+123
```
注意：这里仅仅是对短字符串进行CBC加密运算，对超长字符串甚至文件进行加密计算不可以使用该方式。若有需求请联系作者或自行研究。