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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	keyPassword = "xyzzy"
)

func rsaDecryptTemplate(scheme *tpm2.SigScheme) tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault & ^tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{
			Sign:    scheme,
			KeyBits: 2048,
		},
	}
}

func rsaSigningTemplate(scheme *tpm2.SigScheme) tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault & ^tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{
			Sign:    scheme,
			KeyBits: 2048,
		},
	}
}

func eccSigningTemplate(scheme *tpm2.SigScheme) tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault & ^tpm2.FlagRestricted,
		ECCParameters: &tpm2.ECCParams{
			Sign:    scheme,
			CurveID: tpm2.CurveNISTP256,
		},
	}
}

func createTLSCerts(t *testing.T, key crypto.PublicKey) (*x509.Certificate, *x509.Certificate) {
	t.Helper()

	now := time.Now()

	cakey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	catmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1983),
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24),
		Subject:               pkix.Name{CommonName: "TPM Test Issuer"},
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, catmpl, catmpl, cakey.Public(), cakey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	cacert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1984),
		NotBefore:    now,
		NotAfter:     now.Add(time.Hour * 24),
		Subject:      pkix.Name{CommonName: "TPM Test Client"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, cacert, key, cakey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, cacert
}

func createAndLoadKey(t *testing.T, pub tpm2.Public) (io.ReadWriter, uint32, func()) {
	t.Helper()

	// Get simulated TPM.
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatalf("failed to get TPM simulator: %v", err)
	}

	var storagePub = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	// Create storage key.
	storage, _, _, _, _, _, err := tpm2.CreatePrimaryEx(tpm, tpm2.HandleOwner,
		tpm2.PCRSelection{}, "", "", storagePub)
	if err != nil {
		flushTPM(t, tpm, 0, 0)
		t.Fatalf("failed to create storage key: %v", err)
	}

	// Create and load key.
	private, public, _, _, _, err := tpm2.CreateKey(tpm, storage,
		tpm2.PCRSelection{}, "", keyPassword, pub)
	if err != nil {
		flushTPM(t, tpm, storage, 0)
		t.Fatalf("failed to create key: %v", err)
	}

	handle, _, err := tpm2.Load(tpm, storage, "", public, private)
	if err != nil {
		flushTPM(t, tpm, storage, 0)
		t.Fatalf("failed to load key: %v", err)
	}

	return tpm, uint32(handle), func() { flushTPM(t, tpm, storage, handle) }
}

func flushTPM(t *testing.T, tpm io.ReadWriteCloser, storage, handle tpmutil.Handle) {
	t.Helper()

	if handle != 0 {
		if err := tpm2.FlushContext(tpm, handle); err != nil {
			t.Errorf("failed to flush key: %v", err)
		}
	}

	if storage != 0 {
		if err := tpm2.FlushContext(tpm, storage); err != nil {
			t.Errorf("failed to flush storage key: %v", err)
		}
	}

	if err := tpm.Close(); err != nil {
		t.Errorf("failed to close TPM: %v", err)
	}
}
