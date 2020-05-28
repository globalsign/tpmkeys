/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tpmkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// PrivateKey represents a private key resident on a TPM 2.0 device. RSA and
// ECC private keys are supported for signing, and only RSA keys are supported
// for encryption.
type PrivateKey struct {
	tpmRW            io.ReadWriter
	tpmPath          string
	password         string
	parentPassword   string
	activeHandle     tpmutil.Handle
	persistentHandle tpmutil.Handle
	parentHandle     tpmutil.Handle
	publicBlob       []byte
	privateBlob      []byte
	pubKey           crypto.PublicKey
	scheme           *tpm2.SigScheme
}

// Public returns the public key corresponding to the opaque private key.
func (k *PrivateKey) Public() crypto.PublicKey {
	return k.pubKey
}

// Sign signs digest with the private key.
func (k *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var scheme tpm2.SigScheme

	// Use the signature algorithm specified by the key, or choose an
	// appropriate based on the key type and the signer options.
	if k.scheme == nil || k.scheme.Alg == tpm2.AlgNull {
		switch t := k.pubKey.(type) {
		case *rsa.PublicKey:
			switch opts.(type) {
			case *rsa.PSSOptions:
				scheme.Alg = tpm2.AlgRSAPSS

			default:
				scheme.Alg = tpm2.AlgRSASSA
			}

		case *ecdsa.PublicKey:
			scheme.Alg = tpm2.AlgECDSA

		default:
			return nil, fmt.Errorf("unsupported public key type: %T", t)
		}
	} else {
		scheme.Alg = k.scheme.Alg
	}

	// Select a hash algorithm based on the signer options.
	switch opts.HashFunc() {
	case crypto.SHA1:
		scheme.Hash = tpm2.AlgSHA1

	case crypto.SHA256:
		scheme.Hash = tpm2.AlgSHA256

	case crypto.SHA384:
		scheme.Hash = tpm2.AlgSHA384

	case crypto.SHA512:
		scheme.Hash = tpm2.AlgSHA512

	default:
		return nil, fmt.Errorf("unsupported hash function: %d", opts.HashFunc())
	}

	// Sign digest.
	rw, handle, closeFunc, err := k.getHandle()
	if err != nil {
		return nil, err
	}
	defer closeFunc()

	sig, err := tpm2.Sign(rw, handle, k.password, digest, &scheme)
	if err != nil {
		return nil, err
	}

	// Return signature based on key type.
	var sigBytes []byte

	switch {
	case sig.RSA != nil:
		sigBytes = sig.RSA.Signature

	case sig.ECC != nil:
		tmp := struct {
			R *big.Int
			S *big.Int
		}{
			R: sig.ECC.R,
			S: sig.ECC.S,
		}

		sigBytes, err = asn1.Marshal(tmp)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC signature: %v", err)
		}
	}

	return sigBytes, nil
}

// Decrypt decrypts msg with the private key.
func (k *PrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	var scheme tpm2.AsymScheme
	var label string

	switch o := opts.(type) {
	case *rsa.OAEPOptions:
		scheme.Alg = tpm2.AlgOAEP

		// tpm2.RSADecrypt appends a null octet to the label passed in, but
		// rsa.EncryptOAEP does not, so the label provided will likely include
		// it. To avoid including it twice, we check here if the last byte in
		// the provided label is a null octet, and we remove it if it is.
		if l := len(o.Label); l > 0 && o.Label[l-1] == 0 {
			label = string(o.Label[:l-1])
		} else {
			label = string(o.Label)
		}

		switch o.Hash {
		case crypto.SHA1:
			scheme.Hash = tpm2.AlgSHA1

		case crypto.SHA256:
			scheme.Hash = tpm2.AlgSHA256

		case crypto.SHA384:
			scheme.Hash = tpm2.AlgSHA384

		case crypto.SHA512:
			scheme.Hash = tpm2.AlgSHA512

		default:
			return nil, fmt.Errorf("unsupported hash function: %d", o.Hash)
		}

	default:
		scheme.Alg = tpm2.AlgRSAES
		scheme.Hash = tpm2.AlgNull
	}

	// Decrypt message.
	rw, handle, closeFunc, err := k.getHandle()
	if err != nil {
		return nil, err
	}
	defer closeFunc()

	return tpm2.RSADecrypt(rw, handle, k.password, msg, &scheme, label)
}

// getHandle returns an io.ReadWriter for a TPM, a key handle, and a cleanup
// function. The return values vary based on which constructor function was
// used to create the private key.
func (k *PrivateKey) getHandle() (io.ReadWriter, tpmutil.Handle, func(), error) {
	if k.activeHandle != 0 {
		return k.tpmRW, k.activeHandle, func() {}, nil
	}

	tpm, err := tpm2.OpenTPM(k.tpmPath)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to open TPM: %v", err)
	}

	if k.persistentHandle != 0 {
		return tpm, k.persistentHandle, func() { tpm.Close() }, nil
	}

	handle, _, err := tpm2.Load(tpm, k.parentHandle, k.parentPassword, k.publicBlob, k.privateBlob)
	if err != nil {
		tpm.Close()
		return nil, 0, nil, fmt.Errorf("failed to load key: %v", err)
	}

	return tpm, handle, func() {
		tpm2.FlushContext(tpm, handle)
		tpm.Close()
	}, nil
}

// NewFromActiveHandle returns a private key object representing the key
// referred to by the specified active handle. The caller is responsible for
// ensuring that the handle for the key is not changed, and the io.ReadWriter
// is not closed, until the returned key will no longer be used. Since this
// function accepts an io.ReadWriter, is it also suitable for connecting to
// a TPM simulator.
func NewFromActiveHandle(rw io.ReadWriter, handle uint32, password string) (*PrivateKey, error) {
	pubKey, scheme, err := publicKeyAndScheme(rw, tpmutil.Handle(handle))
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		tpmRW:        rw,
		password:     password,
		activeHandle: tpmutil.Handle(handle),
		pubKey:       pubKey,
		scheme:       scheme,
	}, nil
}

// NewFromPersistentHandle returns a private key object representing the key
// referred to by the specified persistent handle, using the TPM at the specified
// path. A connection to the TPM is opened and closed with each use of the key,
// so the returned key is usable for as long as the key remains at that
// persistent handle.
func NewFromPersistentHandle(path string, handle uint32, password string) (*PrivateKey, error) {
	tpm, err := tpm2.OpenTPM(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %v", err)
	}
	defer tpm.Close()

	pubKey, scheme, err := publicKeyAndScheme(tpm, tpmutil.Handle(handle))
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		tpmPath:          path,
		password:         password,
		persistentHandle: tpmutil.Handle(handle),
		pubKey:           pubKey,
		scheme:           scheme,
	}, nil
}

// NewFromBlobs returns a private key object representing the key referred to
// by the provided public and private area blobs. A connection to the TPM is
// opened and closed, and the key loaded and flushed, with each use of the key,
// so the returned key is usable for as long as the parent key remains at the
// specified persistent handle.
func NewFromBlobs(
	path string,
	parent uint32,
	parentPassword string,
	pubBlob, privBlob []byte,
	password string,
) (*PrivateKey, error) {
	tpm, err := tpm2.OpenTPM(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %v", err)
	}
	defer tpm.Close()

	handle, _, err := tpm2.Load(tpm, tpmutil.Handle(parent), parentPassword, pubBlob, privBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %v", err)
	}
	defer tpm2.FlushContext(tpm, handle)

	pubKey, scheme, err := publicKeyAndScheme(tpm, handle)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		tpmPath:        path,
		password:       password,
		parentPassword: parentPassword,
		parentHandle:   tpmutil.Handle(parent),
		publicBlob:     pubBlob,
		privateBlob:    privBlob,
		pubKey:         pubKey,
		scheme:         scheme,
	}, nil
}

// publicKeyAndScheme reads a public area from an active handle and returns the
// public key and signature scheme, if any.
func publicKeyAndScheme(rw io.ReadWriter, handle tpmutil.Handle) (crypto.PublicKey, *tpm2.SigScheme, error) {
	pub, _, _, err := tpm2.ReadPublic(rw, handle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public area from TPM: %v", err)
	}

	pubKey, err := pub.Key()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key from public area: %v", err)
	}

	// If the object specifies a signature scheme, store it.
	var scheme *tpm2.SigScheme

	switch {
	case pub.RSAParameters != nil:
		scheme = pub.RSAParameters.Sign

	case pub.ECCParameters != nil:
		scheme = pub.ECCParameters.Sign

	default:
		return nil, nil, errors.New("only RSA and ECC keys supported")
	}

	return pubKey, scheme, nil
}
