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

import (
	"crypto/elliptic"
	"math/big"
	"encoding/asn1"
	"errors"
	"fmt"



	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm/sm2"
)


type SM2Signature struct {
	R, S *big.Int
}

var (
	// curveHalfOrders contains the precomputed curve group orders halved.
	// It is used to ensure that signature' S value is lower or equal to the
	// curve group order halved. We accept only low-S signatures.
	// They are precomputed for efficiency reasons.
	curveHalfOrders map[elliptic.Curve]*big.Int = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
		sm2.P256Sm2(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
	}
)



func MarshalSM2Signature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(SM2Signature{r, s})
}

func UnmarshalSM2Signature(raw []byte) (*big.Int, *big.Int, error) {
	// Unmarshal
	sig := new(SM2Signature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	// Validate sig
	if sig.R == nil {
		return nil, nil, errors.New("Invalid signature. R must be different from nil.")
	}
	if sig.S == nil {
		return nil, nil, errors.New("Invalid signature. S must be different from nil.")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("Invalid signature. R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("Invalid signature. S must be larger than zero")
	}

	return sig.R, sig.S, nil
}



type gmsm2Signer struct{}

func (s *gmsm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// return signECDSA(k.(*ecdsaPrivateKey).privKey, digest, opts)

	return k.(*gmsm2PrivateKey).privKey.Sign(digest)

}

type gmsm2PrivateKeyVerifier struct{}

func (v *gmsm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// return verifyECDSA(&(k.(*ecdsaPrivateKey).privKey.PublicKey), signature, digest, opts)

	res := k.(*gmsm2PrivateKey).privKey.PublicKey.Verify(digest, signature)
	return res, nil
}

type gmsm2PublicKeyKeyVerifier struct{}

func (v *gmsm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// return verifyECDSA(k.(*ecdsaPublicKey).pubKey, signature, digest, opts)

	res := k.(*gmsm2PublicKey).pubKey.Verify(digest, signature)

	return res, nil
}


func SignatureToLowS(k *sm2.PublicKey, signature []byte) ([]byte, error) {
	r, s, err := UnmarshalSM2Signature(signature)
	if err != nil {
		return nil, err
	}

	s, modified, err := ToLowS(k, s)
	if err != nil {
		return nil, err
	}

	if modified {
		return MarshalSM2Signature(r, s)
	}
	return signature, nil
}

func ToLowS(k *sm2.PublicKey, s *big.Int) (*big.Int, bool, error) {
	lowS, err := IsLowS(k, s)
	if err != nil {
		return nil, false, err
	}

	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		s.Sub(k.Params().N, s)

		return s, true, nil
	}

	return s, false, nil
}

// IsLow checks that s is a low-S
func IsLowS(k *sm2.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("Curve not recognized [%s]", k.Curve)
	}

	return s.Cmp(halfOrder) != 1, nil

}
