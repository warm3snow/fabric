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

package sw

import (
	"errors"
	"fmt"

	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"reflect"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/warm3snow/gmsm/sm2"
	sm2Utils "github.com/warm3snow/gmsm/utils"
)

type sm2PKIXPublicKeyImportOptsKeyImporter struct{}

func (*sm2PKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := utils.DERToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to sm2 public key [%s]", err)
	}

	sm2PK, ok := lowLevelKey.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to sm2 public key. Invalid raw material.")
	}

	return &sm2PublicKey{sm2PK}, nil
}

type sm2PrivateKeyImportOptsKeyImporter struct{}

func (*sm2PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[SM2DERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[SM2DERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := utils.DERToPrivateKey(der)
	//lowLevelKey, err := sm2.ParseSm2PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to sm2 public key [%s]", err)
	}

	sm2SK, ok := lowLevelKey.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to sm2 private key. Invalid raw material.")
	}

	return &sm2PrivateKey{sm2SK}, nil
	//	return &sm2PrivateKey{lowLevelKey}, nil
}

type sm2GoPublicKeyImportOptsKeyImporter struct{}

func (*sm2GoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	lowLevelKey, ok := raw.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *sm2.PublicKey.")
	}

	return &sm2PublicKey{lowLevelKey}, nil
}

type aes256ImportKeyOptsKeyImporter struct{}

func (*aes256ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if aesRaw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	if len(aesRaw) != 32 {
		return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 32 bytes", len(aesRaw))
	}

	return &aesPrivateKey{utils.Clone(aesRaw), false}, nil
}

type hmacImportKeyOptsKeyImporter struct{}

func (*hmacImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	aesRaw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(aesRaw) == 0 {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	return &aesPrivateKey{utils.Clone(aesRaw), false}, nil
}

type ecdsaPKIXPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := utils.DERToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaPK, ok := lowLevelKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA public key. Invalid raw material.")
	}

	return &ecdsaPublicKey{ecdsaPK}, nil
}

type ecdsaPrivateKeyImportOptsKeyImporter struct{}

func (*ecdsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw. It must not be nil.")
	}

	lowLevelKey, err := utils.DERToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("Failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to ECDSA private key. Invalid raw material.")
	}

	return &ecdsaPrivateKey{ecdsaSK}, nil
}

type ecdsaGoPublicKeyImportOptsKeyImporter struct{}

func (*ecdsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	lowLevelKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *ecdsa.PublicKey.")
	}

	return &ecdsaPublicKey{lowLevelKey}, nil
}

type rsaGoPublicKeyImportOptsKeyImporter struct{}

func (*rsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	lowLevelKey, ok := raw.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *rsa.PublicKey.")
	}

	return &rsaPublicKey{lowLevelKey}, nil
}

type x509PublicKeyImportOptsKeyImporter struct {
	bccsp *impl
}

func (ki *x509PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	cert, ok := raw.(*x509.Certificate)
	if ok {
		x509Cert := sm2Utils.ParseX509Certificate2Sm2(cert)
		//x509 certificate
		pk := x509Cert.PublicKey
		//should use key type to indenfify ecdsa and sm2, this problem should be solved in x509 certificate XXX
		if x509Cert.SignatureAlgorithm == sm2.SM2WithSHA256 {
			switch pk.(type) {
			case *ecdsa.PublicKey:
				logger.Info("1...sm2 key import...")
				tmpK, _ := sm2.GenerateKey()
				sm2pk := &tmpK.PublicKey
				sm2pk.X, sm2pk.Y = pk.(*ecdsa.PublicKey).X, pk.(*ecdsa.PublicKey).Y
				return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{})].KeyImport(
					//pk.(*sm2.PublicKey),
					sm2pk,
					&bccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
			default:
				return nil, errors.New("sm2 x509 Certificate's public key type not recognized. Supported keys: [SM2]")
			}
		} else {
			switch pk.(type) {
			case *ecdsa.PublicKey:
				logger.Info("...ecdsa key import...")
				return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
					pk,
					&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
			case *rsa.PublicKey:
				logger.Info("...rsa key import...")
				return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.RSAGoPublicKeyImportOpts{})].KeyImport(
					pk,
					&bccsp.RSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
			case *sm2.PublicKey:
				logger.Info("2...sm2 key import...")
				return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{})].KeyImport(
					pk.(*sm2.PublicKey),
					&bccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
			default:
				//fmt.Println("x509 Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
				return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
			}
		}

	} else {
		cert, ok := raw.(*sm2.Certificate)
		if ok {
			pk := cert.PublicKey
			switch pk.(type) {
			case *sm2.PublicKey:
				logger.Info("3...sm2 key import...")
				return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
					pk,
					&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
			default:
				return nil, errors.New("Certificate's public key type not recognized. Supported keys: [SM2]")
			}

		}
	}

	return nil, errors.New("Invalid raw material. Expected *x509.Certificate.")
}
