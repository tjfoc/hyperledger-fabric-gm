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
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm"

	"io/ioutil"
	"path/filepath"

	"github.com/hyperledger/fabric/bccsp/gm/sm2"
	"github.com/hyperledger/fabric/common/tools/cryptogen/csp"
)

type CA struct {
	Name string
	//SignKey  *ecdsa.PrivateKey
	Signer      crypto.Signer
	SignCert    *x509.Certificate
	SignSm2Cert *sm2.Certificate
	Sm2Key      bccsp.Key
}

// NewCA creates an instance of CA and saves the signing key pair in
// baseDir/name
func NewCA(baseDir, org, name string) (*CA, error) {

	var response error
	var ca *CA

	err := os.MkdirAll(baseDir, 0755)
	if err == nil {
		//priv, signer, err := csp.GeneratePrivateKey(baseDir)
		priv, _, err := csp.GeneratePrivateKey(baseDir)
		response = err
		if err == nil {
			// get public signing certificate
			//ecPubKey, err := csp.GetECPublicKey(priv)
			sm2PubKey, err := csp.GetSM2PublicKey(priv)
			response = err
			if err == nil {
				template := x509Template()
				//this is a CA
				template.IsCA = true
				template.KeyUsage |= x509.KeyUsageDigitalSignature |
					x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign |
					x509.KeyUsageCRLSign
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}

				//set the organization for the subject
				subject := subjectTemplate()
				subject.Organization = []string{org}
				subject.CommonName = name

				template.Subject = subject
				template.SubjectKeyId = priv.SKI()

				// x509Cert, err := genCertificateECDSA(baseDir, name, &template, &template,
				// 	ecPubKey, signer)
				sm2cert := gm.ParseX509Certificate2Sm2(&template)

				sm2cert.PublicKey = sm2PubKey

				x509Cert, err := genCertificateGMSM2(baseDir, name, sm2cert, sm2cert, sm2PubKey, priv)
				response = err
				if err == nil {
					ca = &CA{
						Name: name,
						//Signer: signer,
						//SignCert: x509Cert,
						SignSm2Cert: x509Cert,
						Sm2Key:      priv,
					}
				}
			}
		}
	}
	return ca, response
}

// SignCertificate creates a signed certificate based on a built-in template
// and saves it in baseDir/name
func (ca *CA) SignCertificate(baseDir, name string, sans []string, pub *sm2.PublicKey,
	ku x509.KeyUsage, eku []x509.ExtKeyUsage) (*sm2.Certificate, error) {

	template := x509Template()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	//set the organization for the subject
	subject := subjectTemplate()
	subject.CommonName = name

	template.Subject = subject
	template.DNSNames = sans
	template.PublicKey = pub

	// cert, err := genCertificateECDSA(baseDir, name, &template, ca.SignCert,
	// 	pub, ca.Signer)

	sm2Tpl := gm.ParseX509Certificate2Sm2(&template)
	cert, err := genCertificateGMSM2(baseDir, name, sm2Tpl, ca.SignSm2Cert, pub, ca.Sm2Key)

	if err != nil {
		return nil, err
	}

	return cert, nil
}

// default template for X509 subject
func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"US"},
		Locality: []string{"San Francisco"},
		Province: []string{"California"},
	}
}

// default template for X509 certificates
func x509Template() x509.Certificate {

	//generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	now := time.Now()
	//basic template to use
	x509 := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour), //~ten years
		BasicConstraintsValid: true,
	}
	return x509

}

// generate a signed X509 certficate using ECDSA
func genCertificateECDSA(baseDir, name string, template, parent *x509.Certificate, pub *ecdsa.PublicKey,
	priv interface{}) (*x509.Certificate, error) {

	//create the x509 public cert
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	//write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	certFile, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	//pem encode the cert
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certFile.Close()
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}

//generate a signed X509 certficate using GMSM2
func genCertificateGMSM2(baseDir, name string, template, parent *sm2.Certificate, pub *sm2.PublicKey,
	key bccsp.Key) (*sm2.Certificate, error) {

	//create the x509 public cert
	certBytes, err := gm.CreateCertificateToMem(template, parent, key)

	if err != nil {
		return nil, err
	}

	//write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	err = ioutil.WriteFile(fileName, certBytes, os.FileMode(0666))

	// certFile, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}

	// //pem encode the cert
	// err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	// certFile.Close()
	// if err != nil {
	// 	return nil, err
	// }
	// fmt.Println("xxx end Encode")
	//x509Cert, err := sm2.ReadCertificateFromPem(fileName)

	x509Cert, err := sm2.ReadCertificateFromMem(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil

}
