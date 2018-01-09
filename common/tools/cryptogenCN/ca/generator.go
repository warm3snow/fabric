/*
Copyright Beijing Sansec Technology Development Co., Ltd. 2017 All Rights Reserved.
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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"path/filepath"

	cspx509 "github.com/hyperledger/fabric/bccsp/x509"
	"github.com/hyperledger/fabric/common/tools/cryptogenCN/csp"
)

type CA struct {
	Name string
	//SignKey  *sm2.PrivateKey
	Signer   crypto.Signer
	SignCert *x509.Certificate
}

// NewCA creates an instance of CA and saves the signing key pair in
// baseDir/name
func NewCA(baseDir, org, name string) (*CA, error) {

	var response error
	var ca *CA

	err := os.MkdirAll(baseDir, 0755)
	if err == nil {
		priv, signer, err := csp.GeneratePrivateKey(baseDir)
		response = err
		if err == nil {
			// get public signing certificate
			pubKey, err := csp.GetPublicKey(priv)
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
				subject.OrganizationalUnit = []string{"WWW"}
				subject.CommonName = name

				template.Subject = subject
				template.SubjectKeyId = priv.SKI()

				//TODO TODO TODO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				cert, err := genCertificate(baseDir, name, &template, &template,
					pubKey, signer)
				response = err
				if err == nil {
					ca = &CA{
						Name:     name,
						Signer:   signer,
						SignCert: cert,
					}
				}
			}
		}
	}
	return ca, response
}

// SignCertificate creates a signed certificate based on a built-in template
// and saves it in baseDir/name
func (ca *CA) SignCertificate(baseDir, name string, sans []string, pub interface{},
	ku x509.KeyUsage, eku []x509.ExtKeyUsage) (*x509.Certificate, error) {

	template := x509Template()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	//set the organization for the subject
	subject := subjectTemplate()
	subject.OrganizationalUnit = []string{"COP"}
	subject.CommonName = name

	template.Subject = subject
	template.DNSNames = sans

	cert, err := genCertificate(baseDir, name, &template, ca.SignCert,
		pub, ca.Signer)

	if err != nil {
		return nil, err
	}

	return cert, nil
}

// default template for sm2 subject
func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"CN"},
		Locality: []string{"JiNan"},
		Province: []string{"ShanDong Province"},
	}
}

// generate a signed certficate using SM2 | ECDSA
func genCertificate(baseDir, name string, template, parent *x509.Certificate, pub interface{},
	priv interface{}) (*x509.Certificate, error) {

	//create the public cert
	certBytes, err := cspx509.CreateCertificate(rand.Reader, template, parent, pub, priv)
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

	x509Cert, err := cspx509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}

type TlsCA struct {
	Name     string
	Signer   crypto.Signer
	SignCert *x509.Certificate
}

// NewCA creates an instance of CA and saves the signing key pair in
// baseDir/name
func NewTlsCA(baseDir, org, name string) (*TlsCA, error) {

	var response error
	var ca *TlsCA

	err := os.MkdirAll(baseDir, 0755)
	if err == nil {
		//tls key not in hsm, implemented in another way
		priv, signer, err := csp.GenerateTlsPrivateKey(baseDir)
		//priv, signer, err := csp.GeneratePrivateKey(baseDir)
		response = err
		if err == nil {
			// get public signing certificate
			pubKey, err := csp.GetECPublicKey(priv)
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

				x509Cert, err := genCertificate(baseDir, name, &template, &template, pubKey, signer)
				response = err
				if err == nil {
					ca = &TlsCA{
						Name:     name,
						Signer:   signer,
						SignCert: x509Cert,
					}
				}
			}
		}
	}
	return ca, response
}

// SignCertificate creates a signed certificate based on a built-in template
// and saves it in baseDir/name
func (ca *TlsCA) SignCertificate(baseDir, name string, sans []string, pub interface{},
	ku x509.KeyUsage, eku []x509.ExtKeyUsage) (*x509.Certificate, error) {

	template := x509Template()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	//set the organization for the subject
	subject := subjectTemplate()
	subject.CommonName = name

	template.Subject = subject
	template.DNSNames = sans

	cert, err := genCertificate(baseDir, name, &template, ca.SignCert, pub, ca.Signer)

	if err != nil {
		return nil, err
	}

	return cert, nil
}

// default template for X509 subject
/*func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"US"},
		Locality: []string{"San Francisco"},
		Province: []string{"California"},
	}
}*/

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
