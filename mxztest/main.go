/*

	Teset demo

*/

package main

import (
	"bytes"

	"crypto/sha256"

	"crypto/sha512"

	"encoding/hex"

	"encoding/json"

	"encoding/pem"

	"flag"

	"fmt"

	"io/ioutil"

	"os"

	"github.com/hyperledger/fabric/bccsp"

	"github.com/hyperledger/fabric/bccsp/factory"

	swgm "github.com/hyperledger/fabric/bccsp/gm"

	"github.com/spf13/viper"

	"golang.org/x/crypto/sha3"
)

type testConfig struct {
	securityLevel int

	hashFamily string
}

var (
	currentKS bccsp.KeyStore

	currentBCCSP bccsp.BCCSP

	currentTestConfig testConfig
)

func initKeyStore() {

	//fmt.Printf("os.path:%s \n", os.TempDir())

	// pwd := [] byte("abc")

	ks, err := swgm.NewFileBasedKeyStore(nil, "/var/tmp/gmks", false)

	if err != nil {

		fmt.Printf("Failed initiliazing KeyStore [%s]", err)

		os.Exit(-1)

	}

	currentKS = ks

	tests := []testConfig{

		{256, "SHA2"},

		{256, "SHA3"},

		{384, "SHA2"},

		{384, "SHA3"},
	}

	// tests := []testConfig{

	// 	{256, "GMSM3"},

	// }

	for _, config := range tests {

		var err error

		currentTestConfig = config

		currentBCCSP, err = swgm.New(config.securityLevel, config.hashFamily, currentKS)

		if err != nil {

			fmt.Printf("Failed initiliazing BCCSP at [%d, %s]: [%s]", config.securityLevel, config.hashFamily, err)

			os.Exit(-1)

		}

	}

}

func testSignVfy(key bccsp.Key) {

	digest := []byte("hello world.this is my fabric!")

	fmt.Printf("key is Private？[%v]\n", key.Private())

	signer, err := currentBCCSP.Sign(key, digest, nil)

	if err != nil {

		fmt.Printf("Sign error [%s] \n", err)

	}

	puk, _ := key.PublicKey()

	fmt.Printf("puk is Private？[%v]\n", puk.Private())

	//公钥验签

	pukres, err := currentBCCSP.Verify(puk, signer, digest, nil)

	if err != nil {

		fmt.Printf("Verify error [%s] \n", err)

	}

	fmt.Print("公钥验签结果:")

	fmt.Println(pukres)

	//私钥验签 （内部将私钥转成了公钥）

	res, err := currentBCCSP.Verify(key, signer, digest, nil)

	if err != nil {

		fmt.Printf("Verify error [%s] \n", err)

	}

	fmt.Print("私钥(内转)验签结果:")

	fmt.Println(res)

}

func main() {

	//ConfigBCCSP()

	// gbccsp := GetBCCSP()

	// if gbccsp == nil{

	// 	fmt.Println("gbccsp is nil ")

	// 	return

	// }

	initKeyStore()

	// key := testKeyGen()

	// fmt.Printf("key:%T", key)

	// pk, err := key.PublicKey()

	// if err != nil {

	// 	fmt.Printf("get pk err:%s\n", err)

	// }

	// err := currentKS.StoreKey(key)

	// if err != nil {
	// 	fmt.Printf("store err:%s\n", err)
	// }

	//sw

	//k := testGetKey("fafc10181e994b3dc52f6080f3a8009ce3b51f6058818f8f1348eed8f0125a6b")

	// k := testGetKey("a69850a9332f06b42bc8a113ebd074fd1895b473eba5e4266697df8aab0f8493")

	// pk, err := k.PublicKey()

	// if err != nil {

	// 	fmt.Printf("get pk err:%s\n", err)

	// }

	// err = currentKS.StoreKey(pk)

	// if err != nil {

	// 	fmt.Printf("store err:%s\n", err)

	// }

	//gm

	key := testGetKey("a69850a9332f06b42bc8a113ebd074fd1895b473eba5e4266697df8aab0f8493")

	//k := testGetKey("574d253e26c6c8c7b6f0fb18f561107083d414ba652aa4fad20d92f3d52a8260")

	// testKeyImport()

	// testEncrypt(k)

	testSignVfy(key)

	// diffHash(currentBCCSP)

	// raw := []byte("0123456789ABCDEF0123456789ABCDEF")

	// raw, _ := swgm.GetRandomBytes(32)

	// fmt.Printf("keyByte：%x \n", raw)

	// k, err := currentBCCSP.KeyImport(raw, &bccsp.AES256ImportKeyOpts{Temporary: false}) //AES128KeyGenOpts

	// if err != nil {

	// 	fmt.Printf("currentBCCSP.KeyImport err: [%s] ", err)

	// }

	// fmt.Println(k)

	// aesDecrypto(k)

	//sm4Crypto()

	//f := &factory.SWFactory{}

	// f := &factory.GMFactory{}

	// opts := &factory.FactoryOpts{

	// 	ProviderName: "GM",

	// 	SwOpts: &factory.SwOpts{

	// 		SecLevel:   256,

	// 		HashFamily: "SHA2",

	// 		// 		FileKeystore: &FileKeystoreOpts{KeyStorePath: os.TempDir()},

	// 	},

	// }

	// csp, err := f.Get(opts)

	// fmt.Println(csp)

	// fmt.Println(err)

}

//测试 KeyImport 函数

func testKeyImport() bccsp.Key {

	fmt.Println("begin   xxxx  testKeyImport  xxxxx ")

	//非对称密钥 与 AES KeyImport 都是 der

	raw, err := ioutil.ReadFile("/var/tmp/ee663eea08b4a090ac2875c598265c3d6ad936a403324c2d75d9a1be50da5ed0_key")

	if err != nil {

		fmt.Printf("ReadFile error [%s]\n", err)

	}

	block, _ := pem.Decode(raw)

	der := block.Bytes

	fmt.Printf("der.len[%d]\n", len(der))

	// opts := &bccsp.AES256ImportKeyOpts{} //sw

	//opts := &bccsp.ECDSAPrivateKeyImportOpts{} //sw

	//opts := &bccsp.ECDSAPKIXPublicKeyImportOpts{} //sw

	//opts := &bccsp.GMSM2PrivateKeyImportOpts{}

	//opts := &bccsp.GMSM2PublicKeyImportOpts{}

	opts := &bccsp.GMSM4ImportKeyOpts{}

	k, err := currentBCCSP.KeyImport(der, opts)

	if err != nil {

		fmt.Printf("KeyImport error [%s]\n", err)

	}

	fmt.Printf("key is privateKey? %v\n", k.Private())

	fmt.Printf("key is symmetric ? %v\n", k.Symmetric())

	pk, err := k.PublicKey()

	if err != nil {

		fmt.Printf("get pk err: %s\n", err)

	}

	fmt.Printf("public key: %T\n", pk)

	fmt.Println()

	return k

}

//测试证书注册

func testKeyGen() bccsp.Key {

	//keyGenOpt := &bccsp.GMSM4KeyGenOpts{} //sm4

	keyGenOpt := &bccsp.GMSM2KeyGenOpts{} //sm2

	//keyGenOpt := &bccsp.ECDSAKeyGenOpts{} //ecdsa

	// keyGenOpt := &bccsp.AES256KeyGenOpts{} //aes

	key, err := currentBCCSP.KeyGen(keyGenOpt)

	if err != nil {

		fmt.Printf("注册证书失败 :%s\n", err)

	} else {

		fmt.Printf("KeyGen successful. %T \n", keyGenOpt)

	}

	return key

}

//测试 GetKey 函数

func testGetKey(keyname string) bccsp.Key {

	fmt.Println("xxxxx testGetKey  keyName :" + keyname)

	ski, _ := hex.DecodeString(keyname)

	k, err := currentBCCSP.GetKey(ski)

	if err != nil {

		fmt.Printf("get ski key error [%s]\n", err)

	}

	fmt.Printf("key is privateKey? %v\n", k.Private())

	fmt.Printf("key is symmetric ? %v\n", k.Symmetric())

	pk, err := k.PublicKey()

	if err != nil {

		fmt.Printf("get pk err: %s\n", err)

	}

	fmt.Printf("public key: %T\n", pk)

	fmt.Println()

	return k

}

// ConfigBCCSP 配置

func ConfigBCCSP() {

	flag.Parse()

	var jsonBCCSP, yamlBCCSP *factory.FactoryOpts

	jsonCFG := []byte(

		`{ "default": "SW", "SW":{ "security": 384, "hash": "SHA3" } }`)

	err := json.Unmarshal(jsonCFG, &jsonBCCSP)

	if err != nil {

		fmt.Printf("Could not parse JSON config [%s]", err)

	}

	var yamlCFG = `

	BCCSP:

		default: SW

		SW:

			Hash: SHA3

			Security: 256`

	viper.SetConfigType("yaml")

	err = viper.ReadConfig(bytes.NewBuffer([]byte(yamlCFG)))

	if err != nil {

		fmt.Printf("Could not read YAML config [%s]\n", err)

	}

	err = viper.UnmarshalKey("bccsp", &yamlBCCSP)

	if err != nil {

		fmt.Printf("Could not parse YAML config [%s]\n", err)

	}

	cfgVariations := []*factory.FactoryOpts{

		{

			ProviderName: "SW",

			SwOpts: &factory.SwOpts{

				HashFamily: "SHA2",

				SecLevel: 256,

				Ephemeral: true,
			},
		},

		{},

		{

			ProviderName: "SW",
		},

		jsonBCCSP,

		yamlBCCSP,
	}

	for index, config := range cfgVariations {

		fmt.Printf("Trying configuration [%d]\n", index)

		factory.InitFactories(config)

		factory.InitFactories(nil)

		csp := factory.GetDefault()

		fmt.Println(csp)

	}

}

// GetBCCSP 获取加密服务对象

func GetBCCSP() bccsp.BCCSP {

	fmt.Println("第一次获取 bccsp [sw]")

	bccsp1, error := factory.GetBCCSP("SW")

	if error != nil {

		fmt.Printf("Get BCCSP ERROR [%s] \n", error)

	} else {

		return bccsp1

	}

	fmt.Println("初始化 bccsp ")

	initerror := factory.InitFactories(nil)

	if initerror != nil {

		fmt.Printf("init factory ERROR [%s]\n", initerror)

	}

	fmt.Println("第二次获取 bccsp [sw]")

	bccsp2, error := factory.GetBCCSP("SW")

	if error != nil {

		fmt.Printf("GetBCCSP error [%s]\n", error)

	}

	return bccsp2

}

// 比较 Hash

func diffHash(gbccsp bccsp.BCCSP) {

	// data, err := ioutil.ReadFile("/go/src/github.com/hyperledger/fabric/mxztest/ifile")

	// if err!=nil {

	// 	fmt.Printf("read file err [%s]\n",err)

	// }

	// msg := data

	s := "abc"

	msg := []byte(s)

	var mdStr1 string

	//hashOpt := &bccsp.SHAOpts{}

	hashOpt := &bccsp.GMSM3Opts{}

	//fmt.Printf("SHA OPT [%s]\n", hashOpt.Algorithm())

	hash, err := gbccsp.GetHash(hashOpt)

	if err != nil {

		fmt.Printf("GetHash err [%s]\n", err)

	}

	fmt.Printf("hash.size [%d]\n", hash.Size())

	fmt.Printf("hash.blocksize [%d]\n", hash.BlockSize())

	out, error := gbccsp.Hash(msg, hashOpt)

	if error != nil {

		fmt.Print("hash error:")

		fmt.Println(error)

	} else {

		mdStr1 = hex.EncodeToString(out)

		fmt.Printf("bccsp hash [%s] [%d]\n", mdStr1, len(mdStr1))

	}

	fmt.Println("-----------------------------------")

	//sha2-256

	h256 := sha256.New()

	h256.Write(msg)

	bs256 := h256.Sum(nil)

	mdStr := hex.EncodeToString(bs256)

	fmt.Printf("hash sha2-256 [%s] [%d]\n", mdStr, len(mdStr))

	//sha2-384

	h384 := sha512.New384()

	h384.Write(msg)

	bs384 := h384.Sum(nil)

	mdStr384 := hex.EncodeToString(bs384)

	fmt.Printf("hash sha2-384 [%s] [%d]\n", mdStr384, len(mdStr384))

	//sha3-256

	sha3_256 := sha3.New256()

	sha3_256.Write(msg)

	bs3256 := sha3_256.Sum(nil)

	mdStr3256 := hex.EncodeToString(bs3256)

	fmt.Printf("hash sha3-256 [%s] [%d]\n", mdStr3256, len(mdStr3256))

	//sha3-384

	sha3_384 := sha3.New384()

	sha3_384.Write(msg)

	bs3384 := sha3_384.Sum(nil)

	mdStr3384 := hex.EncodeToString(bs3384)

	fmt.Printf("hash sha3-384 [%s] [%d]\n", mdStr3384, len(mdStr3384))

}

//AES

func aesDecrypto(k bccsp.Key) {

	fmt.Println("in aesDecrypto")

	ct, err := currentBCCSP.Encrypt(k, []byte("Hello World"), &bccsp.AESCBCPKCS7ModeOpts{})

	if err != nil {

		fmt.Printf("Encrypt err: [%s] ", err)

	}

	fmt.Printf("AES 加密：%x \n", ct)

	pt, err := currentBCCSP.Decrypt(k, ct, &bccsp.AESCBCPKCS7ModeOpts{})

	if err != nil {

		fmt.Printf("Decrypt err: [%s] ", err)

	}

	msg := string(pt[:])

	fmt.Printf("AES 解密：%s \n", msg)

}

//测试加解密

func testEncrypt(k bccsp.Key) {

	data := []byte("2222222222222222") //009d758db74fca117fdc4672b0176a24

	//data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	//data := []byte("this is plaintext")

	//raw := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	//raw := []byte("0123456789ABCDEF0123456789ABCDEF")

	//raw, _ := sw.GetRandomBytes(32)

	//fmt.Printf("key byte：%s \n", hex.EncodeToString(raw))

	ct, err := currentBCCSP.Encrypt(k, data, &bccsp.AESCBCPKCS7ModeOpts{})

	if err != nil {

		fmt.Printf("Encrypt err: [%s] ", err)

	}

	fmt.Printf("明文：len: %d [%s]\n", len(data), hex.EncodeToString(data))

	fmt.Printf("SM4 加密：len:%d [%s] \n", len(ct), hex.EncodeToString(ct))

	pt, err := currentBCCSP.Decrypt(k, ct, &bccsp.AESCBCPKCS7ModeOpts{})

	if err != nil {

		fmt.Printf("Decrypt err: [%s] ", err)

	}

	fmt.Printf("SM4 解密：len:%d [%s] \n", len(pt), hex.EncodeToString(pt))

}
