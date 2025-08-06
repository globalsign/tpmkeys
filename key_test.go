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

package tpmkeys_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"

	"github.com/globalsign/tpmkeys"
)

type testHandler struct{}

func (h testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusTeapot)
}

func TestSign(t *testing.T) {
	var testcases = []struct {
		name   string
		tmpl   func(*tpm2.SigScheme) tpm2.Public
		scheme *tpm2.SigScheme
		hash   crypto.SignerOpts
	}{
		{
			name: "RSA/NoScheme/SHA1",
			tmpl: rsaSigningTemplate,
			hash: crypto.SHA1,
		},
		{
			name: "ECC/NoScheme/SHA256",
			tmpl: eccSigningTemplate,
			hash: crypto.SHA256,
		},
		{
			name: "RSA/NoScheme/SHA384",
			tmpl: rsaSigningTemplate,
			hash: crypto.SHA384,
		},
		{
			name: "ECC/NoScheme/SHA512",
			tmpl: eccSigningTemplate,
			hash: crypto.SHA512,
		},
		{
			name: "RSA/RSASSA/SHA512",
			tmpl: rsaSigningTemplate,
			scheme: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA512,
			},
			hash: crypto.SHA512,
		},
		{
			name: "RSA/RSAPSS/SHA384",
			tmpl: rsaSigningTemplate,
			scheme: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSAPSS,
				Hash: tpm2.AlgSHA384,
			},
			hash: &rsa.PSSOptions{Hash: crypto.SHA384},
		},
		{
			name: "ECC/ECDSA/SHA256",
			tmpl: eccSigningTemplate,
			scheme: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			hash: crypto.SHA256,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			pub := tc.tmpl(tc.scheme)

			tpm, handle, closeFunc := createAndLoadKey(t, pub)
			defer closeFunc()

			// Get private signing key.
			key, err := tpmkeys.NewFromActiveHandle(tpm, handle, keyPassword)
			if err != nil {
				t.Fatalf("failed to get private key from active handle: %v", err)
			}

			// Calculate and sign digest.

			hash := tc.hash.HashFunc().New()
			hash.Write([]byte("some random message"))
			digest := hash.Sum(nil)

			sig, err := key.Sign(rand.Reader, digest, tc.hash)
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			// Verify signature.
			switch h := tc.hash.(type) {
			case crypto.Hash:
				switch pk := key.Public().(type) {
				case *rsa.PublicKey:
					err := rsa.VerifyPKCS1v15(pk, h, digest, sig)
					if err != nil {
						t.Fatalf("failed to verify PKCS1v15 signature: %v", err)
					}

				case *ecdsa.PublicKey:
					var esig = struct {
						R *big.Int
						S *big.Int
					}{}

					if _, err := asn1.Unmarshal(sig, &esig); err != nil {
						t.Fatalf("failed to unmarshal ECDSA signature: %v", err)
					}

					if ok := ecdsa.Verify(pk, digest, esig.R, esig.S); !ok {
						t.Fatalf("failed to verify ECDSA signature")
					}

				default:
					t.Fatalf("unexpected public key type: %T", pk)
				}

			case *rsa.PSSOptions:
				pubkey := key.Public().(*rsa.PublicKey)
				err := rsa.VerifyPSS(pubkey, h.HashFunc(), digest, sig, h)
				if err != nil {
					t.Fatalf("failed to verify PSS signature: %v", err)
				}

			default:
				t.Fatalf("unexpected crypto.SignerOpts type: %T", h)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	var testcases = []struct {
		name   string
		tmpl   func(*tpm2.SigScheme) tpm2.Public
		scheme *tpm2.SigScheme
		opts   crypto.DecrypterOpts
	}{
		{
			name: "RSA/OAEP/SHA1",
			tmpl: rsaDecryptTemplate,
			scheme: &tpm2.SigScheme{
				Alg:  tpm2.AlgOAEP,
				Hash: tpm2.AlgSHA1,
			},
			opts: &rsa.OAEPOptions{
				Hash:  crypto.SHA1,
				Label: []byte{'a', 'b', 'a', 'n', 'd', 'o', 'n', 0},
			},
		},
		{
			name: "RSA/OAEP/SHA256",
			tmpl: rsaDecryptTemplate,
			scheme: &tpm2.SigScheme{
				Alg:  tpm2.AlgOAEP,
				Hash: tpm2.AlgSHA256,
			},
			opts: &rsa.OAEPOptions{
				Hash:  crypto.SHA256,
				Label: []byte{'a', 'l', 'l', ' ', 'h', 'o', 'p', 'e', 0},
			},
		},
		{
			name: "RSA/OAEP/SHA384",
			tmpl: rsaDecryptTemplate,
			scheme: &tpm2.SigScheme{
				Alg:  tpm2.AlgOAEP,
				Hash: tpm2.AlgSHA384,
			},
			opts: &rsa.OAEPOptions{
				Hash:  crypto.SHA384,
				Label: []byte{'y', 'e', ' ', 'w', 'h', 'o', 0},
			},
		},
		{
			name: "RSA/OAEP/SHA512",
			tmpl: rsaDecryptTemplate,
			scheme: &tpm2.SigScheme{
				Alg:  tpm2.AlgOAEP,
				Hash: tpm2.AlgSHA512,
			},
			opts: &rsa.OAEPOptions{
				Hash:  crypto.SHA512,
				Label: []byte{'e', 'n', 't', 'e', 'r', 0},
			},
		},
		{
			name: "RSA/OAEP/EmptyLabel",
			tmpl: rsaDecryptTemplate,
			scheme: &tpm2.SigScheme{
				Alg:  tpm2.AlgOAEP,
				Hash: tpm2.AlgSHA256,
			},
			opts: &rsa.OAEPOptions{
				Hash:  crypto.SHA256,
				Label: []byte{},
			},
		},
		{
			name: "RSA/ES",
			tmpl: rsaDecryptTemplate,
			opts: &rsa.PKCS1v15DecryptOptions{},
		},
		{
			name: "RSA/ES/Implicit",
			tmpl: rsaDecryptTemplate,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			pub := tc.tmpl(tc.scheme)

			tpm, handle, closeFunc := createAndLoadKey(t, pub)
			defer closeFunc()

			// Get private decryption key.
			key, err := tpmkeys.NewFromActiveHandle(tpm, handle, keyPassword)
			if err != nil {
				t.Fatalf("failed to get private key from active handle: %v", err)
			}

			pubKey := key.Public().(*rsa.PublicKey)
			plain := []byte("Hello, world!")
			var enc []byte

			// Encrypt something.
			switch opts := tc.opts.(type) {
			case *rsa.OAEPOptions:
				enc, err = rsa.EncryptOAEP(opts.Hash.New(), rand.Reader, pubKey, plain, opts.Label)

			default:
				enc, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, plain)
			}
			if err != nil {
				t.Fatalf("failed to encrypt: %v", err)
			}

			// Decrypt it with the TPM key.
			got, err := key.Decrypt(rand.Reader, enc, tc.opts)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}

			if !bytes.Equal(got, plain) {
				t.Fatalf("got %q, want %q", string(got), string(plain))
			}
		})
	}
}

func TestTLSClient(t *testing.T) {
	var testcases = []struct {
		name string
		tmpl func(*tpm2.SigScheme) tpm2.Public
	}{
		{name: "RSA", tmpl: rsaSigningTemplate},
		{name: "ECC", tmpl: eccSigningTemplate},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			tpm, handle, closeFunc := createAndLoadKey(t, tc.tmpl(nil))
			defer closeFunc()

			// Get private signing key.
			key, err := tpmkeys.NewFromActiveHandle(tpm, handle, keyPassword)
			if err != nil {
				t.Fatalf("failed to get private key from active handle: %v", err)
			}

			// Build a TLS client certificate.
			cert, cacert := createTLSCerts(t, key.Public())

			// Create and configure a test server.
			s := httptest.NewUnstartedServer(testHandler{})
			s.TLS = &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  x509.NewCertPool(),
			}
			s.TLS.ClientCAs.AddCert(cacert)
			s.StartTLS()
			defer s.Close()

			// Make request to test server.
			c := s.Client()
			c.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{
				{
					Certificate: [][]byte{cert.Raw},
					PrivateKey:  key,
					Leaf:        cert,
				},
			}

			req, err := http.NewRequest(http.MethodGet, s.URL, nil)
			if err != nil {
				t.Fatalf("failed to make HTTP request: %v", err)
			}

			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("failed to execute HTTP request: %v", err)
			}

			if resp.StatusCode != http.StatusTeapot {
				t.Fatalf("got status %d, want %d", resp.StatusCode, http.StatusTeapot)
			}
		})
	}
}
