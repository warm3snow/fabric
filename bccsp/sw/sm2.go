/*
Copyright Beijing Sansec Technology Development Co., Ltd. 2017 All Rights Reserved.
Copyright IBM Corp. 2016 All Rights Reserved.

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
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/warm3snow/gmsm/sm2"
)

type SM2Signature struct {
	R, S *big.Int
}

/*
var (
	// curveHalfOrders contains the precomputed curve group orders halved.
	// It is used to ensure that signature' S value is lower or equal to the
	// curve group order halved. We accept only low-S signatures.
	// They are precomputed for efficiency reasons.
	curveHalfOrders map[elliptic.Curve]*big.Int = map[elliptic.Curve]*big.Int{
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
	}
)
*/

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

func signSM2(k *sm2.PrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	r, s, err := sm2.Sign( /*rand.Reader,*/ k, digest)
	if err != nil {
		return nil, err
	}

	/*
		s, _, err = SM2ToLowS(&k.PublicKey, s)
		if err != nil {
			return nil, err
		}
	*/

	return MarshalSM2Signature(r, s)
}

func verifySM2(k *sm2.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	r, s, err := UnmarshalSM2Signature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	/*
		lowS, err := SM2IsLowS(k, s)
		if err != nil {
			return false, err
		}

		if !lowS {
			return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, curveHalfOrders[k.Curve])
		}
	*/

	return sm2.Verify(k, digest, r, s), nil
}

type sm2Signer struct{}

func (s *sm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	return signSM2(k.(*sm2PrivateKey).privKey, digest, opts)
}

type sm2PrivateKeyVerifier struct{}

func (v *sm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifySM2(&(k.(*sm2PrivateKey).privKey.PublicKey), signature, digest, opts)
}

type sm2PublicKeyKeyVerifier struct{}

func (v *sm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifySM2(k.(*sm2PublicKey).pubKey, signature, digest, opts)
}

func SM2SignatureToLowS(k *sm2.PublicKey, signature []byte) ([]byte, error) {
	r, s, err := UnmarshalSM2Signature(signature)
	if err != nil {
		return nil, err
	}

	s, modified, err := SM2ToLowS(k, s)
	if err != nil {
		return nil, err
	}

	if modified {
		return MarshalSM2Signature(r, s)
	}

	return signature, nil
}

// IsLow checks that s is a low-S
func SM2IsLowS(k *sm2.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("Curve not recognized [%s]", k.Curve)
	}

	return s.Cmp(halfOrder) != 1, nil

}

func SM2ToLowS(k *sm2.PublicKey, s *big.Int) (*big.Int, bool, error) {
	lowS, err := SM2IsLowS(k, s)
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
