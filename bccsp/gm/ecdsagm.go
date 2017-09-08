/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gm

import(
	"fmt"
	"github.com/hyperledger/fabric/bccsp"
)

type gmsm2Signer struct{}

func (s *gmsm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// return signECDSA(k.(*ecdsaPrivateKey).privKey, digest, opts)

	return k.(*gmsm2PrivateKey).privKey.Sign(digest)

}

type gmsm2PrivateKeyVerifier struct{}

func (v *gmsm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// return verifyECDSA(&(k.(*ecdsaPrivateKey).privKey.PublicKey), signature, digest, opts)

	fmt.Println("in ecdsagm.go gmsm2PrivateKeyVerifier Verify()")

	res := k.(*gmsm2PrivateKey).privKey.PublicKey.Verify(digest,signature)
	return res,nil
}

type gmsm2PublicKeyKeyVerifier struct{}

func (v *gmsm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// return verifyECDSA(k.(*ecdsaPublicKey).pubKey, signature, digest, opts)

	fmt.Println("in ecdsagm.go ecdsagmPublicKeyKeyVerifier Verify()")

	res := k.(*gmsm2PublicKey).pubKey.Verify(digest,signature)

	return res,nil
}
