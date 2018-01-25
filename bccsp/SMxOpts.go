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

package bccsp

const (
	/*curve parameters
	p=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
	a=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
	b=28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
	n=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
	Gx=32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
	Gy=BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
	*/
	//SM2 EC Digital Signature Algorithm(key gen, import, sign, verify)
	//SM2 EC Signature over GM256 curve y^3=x^3+ax+b.
	SM2 = "SM2"
	//SM2ReRand SM2 key re-randomization for keyderiv
	SM2ReRand = "SM2_RERAND"
	//SM3 Hash Algorithm
	SM3 = "SM3"
	//SM4 Sym Algorithm
	SM4 = "SM4"
)

//SM2KeyGenOpts: options for SM2 key generation.
type SM2KeyGenOpts struct {
	Temporary bool
}

//Algorithm returns the key generation algorithm identifier.
func (opts *SM2KeyGenOpts) Algorithm() string {
	return SM2
}

//Ephemeral returns true if the key to generate has to be ephemeral,
//false otherwise.
func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM2PrivateKeyImportOpts contains options for SM2 private key importation in DER or PKCS#8 format
type SM2PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2PrivateKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM2PublicKeyImportOpts contains options for SM2 key importation from sm2PublicKey
type SM2PublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2PublicKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM2GoPublicKeyImportOpts contains options for SM2 key importation from sm2PublicKey
type SM2GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2GoPublicKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM2PKIXPublicKeyImportOpts contains options for SM2 key importation from sm2PublicKey
type SM2PKIXPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2PKIXPublicKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2PKIXPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

//SM2ReRandKeyOpts contains options for SM2 key re-randomization
type SM2ReRandKeyOpts struct {
	Temporary bool
	Expansion []byte
}

// Algorithm returns the key derivation algorithm identifier (to be used).
func (opts *SM2ReRandKeyOpts) Algorithm() string {
	return SM2ReRand
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2ReRandKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

// ExpansionValue returns the re-randomization factor
func (opts *SM2ReRandKeyOpts) ExpansionValue() []byte {
	return opts.Expansion
}

//SM4KeyGenOpts contains options for SM4 key generation at 128 security level
type SM4KeyGenOpts struct {
	Temporary bool
}

//Algorithm returns the hash algorithm identifier(to be used)
func (opts *SM4KeyGenOpts) Algorithm() string {
	return SM4
}

//Ephemeral returns true if the key to generate has to be ephemeral,
//false otherwise
func (opts *SM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

//SM4CBCPKCS7ModeOpts contains options for SM4 CBC encryption
//with PKCS7 padding
type SM4CBCPKCS7ModeOpts struct{}

//SM3Opts contains options relating to SM3
type SM3Opts struct {
}

//Algorithm returns the hash algorithm identifier(to be used)
func (opts *SM3Opts) Algorithm() string {
	return SM3
}
