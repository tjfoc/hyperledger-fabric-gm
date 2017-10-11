/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

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

func isECDSASignedCert(cert *sm2.Certificate) bool {
	return cert.SignatureAlgorithm == sm2.ECDSAWithSHA1 ||
		cert.SignatureAlgorithm == sm2.ECDSAWithSHA256 ||
		cert.SignatureAlgorithm == sm2.ECDSAWithSHA384 ||
		cert.SignatureAlgorithm == sm2.ECDSAWithSHA512
}

// sanitizeECDSASignedCert checks that the signatures signing a cert
// is in low-S. This is checked against the public key of parentCert.
// If the signature is not in low-S, then a new certificate is generated
// that is equals to cert but the signature that is in low-S.
func sanitizeECDSASignedCert(cert *sm2.Certificate, parentCert *sm2.Certificate) (*sm2.Certificate, error) {
	mylogger.Info("in sanitizeECDSASignedCert")
	if cert == nil {
		return nil, errors.New("Certificate must be different from nil.")
	}
	if parentCert == nil {
		return nil, errors.New("Parent certificate must be different from nil.")
	}

	mylogger.Info("gm.SignatureToLowS")
	expectedSig, err := gm.SignatureToLowS(parentCert.PublicKey.(*ecdsa.PublicKey), cert.Signature)
	if err != nil {
		return nil, err
	}

	mylogger.Info("if sig == cert.Signature ?")
	// if sig == cert.Signature, nothing needs to be done
	if bytes.Equal(cert.Signature, expectedSig) {
		mylogger.Info("true, nothing needs to be done")
		return cert, nil
	}
	// otherwise create a new certificate with the new signature
	mylogger.Info("false ,create a new certificate with the new signature")
	mylogger.Info("1. Unmarshal cert.Raw to get an instance of certificate")

	// 1. Unmarshal cert.Raw to get an instance of certificate,
	//    the lower level interface that represent an sm2 certificate
	//    encoding
	var newCert certificate
	newCert, err = certFromSM2Cert(cert)
	if err != nil {
		return nil, err
	}

	mylogger.Info("2. Change the signature")
	// 2. Change the signature
	newCert.SignatureValue = asn1.BitString{Bytes: expectedSig, BitLength: len(expectedSig) * 8}

	mylogger.Info("3. marshal again newCert. Raw must be nil")
	// 3. marshal again newCert. Raw must be nil
	newCert.Raw = nil
	newRaw, err := asn1.Marshal(newCert)
	if err != nil {
		return nil, err
	}

	mylogger.Info("4. parse newRaw to get an sm2 certificate")
	// 4. parse newRaw to get an sm2 certificate
	return sm2.ParseCertificate(newRaw)
}

// func certFromX509Cert(cert *x509.Certificate) (certificate, error) {
// 	var newCert certificate
// 	_, err := asn1.Unmarshal(cert.Raw, &newCert)
// 	if err != nil {
// 		return certificate{}, err
// 	}
// 	return newCert, nil
// }

func certFromSM2Cert(cert *sm2.Certificate) (certificate, error) {
	var newCert certificate
	_, err := asn1.Unmarshal(cert.Raw, &newCert)
	if err != nil {
		return certificate{}, err
	}
	return newCert, nil
}

// String returns a PEM representation of a certificate
func (c certificate) String() string {
	b, err := asn1.Marshal(c)
	if err != nil {
		return fmt.Sprintf("Failed marshaling cert: %v", err)
	}
	block := &pem.Block{
		Bytes: b,
		Type:  "CERTIFICATE",
	}
	b = pem.EncodeToMemory(block)
	return string(b)
}

// certToPEM converts the given sm2.Certificate to a PEM
// encoded string
func certToPEM(certificate *sm2.Certificate) string {
	cert, err := certFromSM2Cert(certificate)
	if err != nil {
		mspIdentityLogger.Warning("Failed converting certificate to asn1", err)
		return ""
	}
	return cert.String()
}
