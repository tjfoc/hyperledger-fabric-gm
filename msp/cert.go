/*
Copyright IBM Corp. 2017 All Rights Reserved.

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

package msp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
	"errors"

	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/bccsp/gm"
	"github.com/hyperledger/fabric/bccsp/gm/sm2"
	
)

type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

func isECDSASignedCert(cert *x509.Certificate) bool {
	return cert.SignatureAlgorithm == x509.ECDSAWithSHA1 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA256 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA384 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA512
}

func isSM2SignedCert(cert *x509.Certificate) bool {
	sm2cert := gm.ParseX509Certificate2Sm2(cert)
	return sm2cert.SignatureAlgorithm == sm2.SM2WithSHA1 ||
		sm2cert.SignatureAlgorithm == sm2.SM2WithSHA256 ||
		sm2cert.SignatureAlgorithm == sm2.SM2WithSHA384 ||
		sm2cert.SignatureAlgorithm == sm2.SM2WithSHA512
}

// sanitizeECDSASignedCert checks that the signatures signing a cert
// is in low-S. This is checked against the public key of parentCert.
// If the signature is not in low-S, then a new certificate is generated
// that is equals to cert but the signature that is in low-S.
func sanitizeECDSASignedCert(cert *x509.Certificate, parentCert *x509.Certificate) (*x509.Certificate, error) {
	if cert == nil {
		return nil, errors.New("Certificate must be different from nil.")
	}
	if parentCert == nil {
		return nil, errors.New("Parent certificate must be different from nil.")
	}

	expectedSig, err := sw.SignatureToLowS(parentCert.PublicKey.(*ecdsa.PublicKey), cert.Signature)
	if err != nil {
		return nil, err
	}

	// if sig == cert.Signature, nothing needs to be done
	if bytes.Equal(cert.Signature, expectedSig) {
		return cert, nil
	}
	// otherwise create a new certificate with the new signature

	// 1. Unmarshal cert.Raw to get an instance of certificate,
	//    the lower level interface that represent an x509 certificate
	//    encoding
	var newCert certificate
	_, err = asn1.Unmarshal(cert.Raw, &newCert)
	if err != nil {
		return nil, err
	}

	// 2. Change the signature
	newCert.SignatureValue = asn1.BitString{Bytes: expectedSig, BitLength: len(expectedSig) * 8}

	// 3. marshal again newCert. Raw must be nil
	newCert.Raw = nil
	newRaw, err := asn1.Marshal(newCert)
	if err != nil {
		return nil, err
	}

	// 4. parse newRaw to get an x509 certificate
	return x509.ParseCertificate(newRaw)
}


func sanitizeSM2SignedCert(cert *x509.Certificate, parentCert *x509.Certificate) (*x509.Certificate, error) {
	mylogger.Info("entry sanitizeSM2SignedCert")
	if cert == nil {
		return nil, errors.New("Certificate must be different from nil.")
	}
	if parentCert == nil {
		return nil, errors.New("Parent certificate must be different from nil.")
	}
	mylogger.Info("call gm SignatureToLowS")
	sm2puk := parentCert.PublicKey.(sm2.PublicKey)
	expectedSig, err := gm.SignatureToLowS(&sm2puk, cert.Signature)
	if err != nil {
		return nil, err
	}

	// if sig == cert.Signature, nothing needs to be done
	if bytes.Equal(cert.Signature, expectedSig) {
		mylogger.Info("gm.SignatureToLowS equal , sig == cert.Signature, nothing needs to be done ")
		return cert, nil
	}
	return cert, nil
	// otherwise create a new certificate with the new signature

	// 1. Unmarshal cert.Raw to get an instance of certificate,
	//    the lower level interface that represent an x509 certificate
	//    encoding
	// mylogger.Info("xxxx 1.Unmarshal cert")

	// var newCert certificate
	// _, err = asn1.Unmarshal(cert.Raw, &newCert)
	// if err != nil {
	// 	return nil, err
	// }

	// mylogger.Info("xxxx 2.Change the signature")
	// // 2. Change the signature
	// newCert.SignatureValue = asn1.BitString{Bytes: expectedSig, BitLength: len(expectedSig) * 8}

	// // 3. marshal again newCert. Raw must be nil
	// mylogger.Info("xxxx 3. marshal again newCert. Raw must be nil")
	// newCert.Raw = nil
	// newRaw, err := asn1.Marshal(newCert)
	// if err != nil {
	// 	return nil, err
	// }

	// mylogger.Info("xxxx 4. return x509.ParseCertificate")
	// // 4. parse newRaw to get an x509 certificate
	// var x509cert *x509.Certificate
	// sm2cert ,err := sm2.ParseCertificate(newRaw)
	// mylogger.Info("sm2.ParseCertificate(newRaw) retreun  cert=%v",sm2cert)
	// if err != nil {
	// 	x509cert = gm.ParseSm2Certificate2X509(sm2cert)
	// }
	// mylogger.Infof("exit sanitizeSM2SignedCert ParseSm2Certificate2X509 return x509cert is nil ? %T",x509cert==nil)
	// return x509cert , err
}
