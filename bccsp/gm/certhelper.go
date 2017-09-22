package gm

import (
	"crypto/rand"
	"crypto/x509"
	"io"
	"math/big"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/gm/sm2"
)

// //调用SM2接口生成SM2证书
// func CreateCertificateToMem(template, parent *x509.Certificate,key bccsp.Key) (cert []byte,err error) {
// 	pk := key.(*gmsm2PrivateKey).privKey
// 	bigint := getRandBigInt()
// 	if(template.SerialNumber == nil){
// 		template.SerialNumber = bigint
// 	}
// 	if parent.SerialNumber == nil{
// 		parent.SerialNumber = bigint
// 	}

// 	sm2Temcert := ParseX509Certificate2Sm2(template)
// 	sm2Parcert := ParseX509Certificate2Sm2(parent)
// 	switch template.PublicKey.(type){
// 	case sm2.PublicKey:
// 		cert, err = sm2.CreateCertificateToMem(sm2Temcert,sm2Parcert, template.PublicKey.(*sm2.PublicKey),pk)
// 		return
// 	default:
// 		return nil ,fmt.Errorf("gm certhelper not sm2.PublicKey")
// 	}
// }

// //调用SM2接口生成SM2证书请求
// func CreateCertificateRequestToMem(certificateRequest *x509.CertificateRequest,key bccsp.Key) (csr []byte,err error) {
// 	pk := key.(*gmsm2PrivateKey).privKey
// 	sm2Req := ParseX509CertificateRequest2Sm2(certificateRequest)
// 	csr,err = sm2.CreateCertificateRequestToMem(sm2Req,pk)
// 	return
// }

//调用SM2接口生成SM2证书
func CreateCertificateToMem(template, parent *sm2.Certificate, key bccsp.Key) (cert []byte, err error) {
	pk := key.(*gmsm2PrivateKey).privKey

	puk := template.PublicKey.(*sm2.PublicKey)
	cert, err = sm2.CreateCertificateToMem(template, parent, puk, pk)
	return
}

//调用SM2接口生成SM2证书请求
func CreateSm2CertificateRequestToMem(certificateRequest *sm2.CertificateRequest, key bccsp.Key) (csr []byte, err error) {
	pk := key.(*gmsm2PrivateKey).privKey
	csr, err = sm2.CreateCertificateRequestToMem(certificateRequest, pk)
	return
}

// X509 证书请求转换 SM2证书请求
func ParseX509CertificateRequest2Sm2(x509req *x509.CertificateRequest) *sm2.CertificateRequest {
	sm2req := &sm2.CertificateRequest{
		Raw: x509req.Raw, // Complete ASN.1 DER content (CSR, signature algorithm and signature).
		RawTBSCertificateRequest: x509req.RawTBSCertificateRequest, // Certificate request info part of raw ASN.1 DER content.
		RawSubjectPublicKeyInfo:  x509req.RawSubjectPublicKeyInfo,  // DER encoded SubjectPublicKeyInfo.
		RawSubject:               x509req.RawSubject,               // DER encoded Subject.

		Version:            x509req.Version,
		Signature:          x509req.Signature,
		SignatureAlgorithm: sm2.SignatureAlgorithm(x509req.SignatureAlgorithm),

		PublicKeyAlgorithm: sm2.PublicKeyAlgorithm(x509req.PublicKeyAlgorithm),
		PublicKey:          x509req.PublicKey,

		Subject: x509req.Subject,

		// Attributes is the dried husk of a bug and shouldn't be used.
		Attributes: x509req.Attributes,

		// Extensions contains raw X.509 extensions. When parsing CSRs, this
		// can be used to extract extensions that are not parsed by this
		// package.
		Extensions: x509req.Extensions,

		// ExtraExtensions contains extensions to be copied, raw, into any
		// marshaled CSR. Values override any extensions that would otherwise
		// be produced based on the other fields but are overridden by any
		// extensions specified in Attributes.
		//
		// The ExtraExtensions field is not populated when parsing CSRs, see
		// Extensions.
		ExtraExtensions: x509req.ExtraExtensions,

		// Subject Alternate Name values.
		DNSNames:       x509req.DNSNames,
		EmailAddresses: x509req.EmailAddresses,
		IPAddresses:    x509req.IPAddresses,
	}
	return sm2req
}

// X509证书格式转换为 SM2证书格式
func ParseX509Certificate2Sm2(x509Cert *x509.Certificate) *sm2.Certificate {
	sm2cert := &sm2.Certificate{
		Raw:                     x509Cert.Raw,
		RawTBSCertificate:       x509Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo: x509Cert.RawSubjectPublicKeyInfo,
		RawSubject:              x509Cert.RawSubject,
		RawIssuer:               x509Cert.RawIssuer,

		Signature:          x509Cert.Signature,
		SignatureAlgorithm: sm2.SignatureAlgorithm(x509Cert.SignatureAlgorithm),

		PublicKeyAlgorithm: sm2.PublicKeyAlgorithm(x509Cert.PublicKeyAlgorithm),
		PublicKey:          x509Cert.PublicKey,

		Version:      x509Cert.Version,
		SerialNumber: x509Cert.SerialNumber,
		Issuer:       x509Cert.Issuer,
		Subject:      x509Cert.Subject,
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		KeyUsage:     sm2.KeyUsage(x509Cert.KeyUsage),

		Extensions: x509Cert.Extensions,

		ExtraExtensions: x509Cert.ExtraExtensions,

		UnhandledCriticalExtensions: x509Cert.UnhandledCriticalExtensions,

		//ExtKeyUsage:	[]x509.ExtKeyUsage(x509Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage: x509Cert.UnknownExtKeyUsage,

		BasicConstraintsValid: x509Cert.BasicConstraintsValid,
		IsCA:       x509Cert.IsCA,
		MaxPathLen: x509Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: x509Cert.MaxPathLenZero,

		SubjectKeyId:   x509Cert.SubjectKeyId,
		AuthorityKeyId: x509Cert.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            x509Cert.OCSPServer,
		IssuingCertificateURL: x509Cert.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:       x509Cert.DNSNames,
		EmailAddresses: x509Cert.EmailAddresses,
		IPAddresses:    x509Cert.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical: x509Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         x509Cert.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints: x509Cert.CRLDistributionPoints,

		PolicyIdentifiers: x509Cert.PolicyIdentifiers,
	}
	for _, val := range x509Cert.ExtKeyUsage {
		sm2cert.ExtKeyUsage = append(sm2cert.ExtKeyUsage, sm2.ExtKeyUsage(val))
	}

	return sm2cert
}

//随机生成序列号
func getRandBigInt() *big.Int {
	serialNumber := make([]byte, 20)
	_, err := io.ReadFull(rand.Reader, serialNumber)
	if err != nil {
		//return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
	}
	// SetBytes interprets buf as the bytes of a big-endian
	// unsigned integer. The leading byte should be masked
	// off to ensure it isn't negative.
	serialNumber[0] &= 0x7F
	//template.SerialNumber = new(big.Int).SetBytes(serialNumber)
	return new(big.Int).SetBytes(serialNumber)
}
