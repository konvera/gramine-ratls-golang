package gramine_ratls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// RA-TLS Certificate
var certDer []byte
var certPem []byte

// RA-TLS measurements args
var mrenclave []byte
var mrsigner []byte
var isv_prod_id []byte
var isv_svn []byte

func setup() {
	certFile, err := os.ReadFile("test/tls/tlscert.der")
	if err != nil {
		panic("error in opening file")
	}
	certDer = certFile

	certFile, err = os.ReadFile("test/tls/tlscert.pem")
	if err != nil {
		panic("error in opening file")
	}
	certPem = certFile

	mrenclave, _ = hex.DecodeString("f94ccbe6a504676b2edbefdcb8781a512913f7d8864c6f88592a843d0f9d4a66")
	mrsigner, _ = hex.DecodeString("285dd1a739713e723e46f5964310423e21ed08d6d966f890ccb1d4ef9ddec9dd")
	isv_prod_id = []byte{0, 0}
	isv_svn, _ = hex.DecodeString("0000")

	// Set `RA_TLS_ALLOW_OUTDATED_TCB_INSECURE` environment variable to 1
	os.Setenv("RA_TLS_ALLOW_OUTDATED_TCB_INSECURE", "1")

	fmt.Printf("\033[1;33m%s\033[0m", "> Setup completed\n")
}

func MockDERCertificate() []byte {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"ABC Company, INC."},
			Country:       []string{"ABC"},
			Province:      []string{""},
			Locality:      []string{"XYZ"},
			StreetAddress: []string{"XYZ ABC"},
			PostalCode:    []string{"1234"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil
	}

	return caBytes
}

func MockPEMCertificate() []byte {
	return []byte(`-----BEGIN CERTIFICATE-----
	MIIB0zCCAX2gAwIBAgIJAI/M7BYjwB+uMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
	BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
	aWRnaXRzIFB0eSBMdGQwHhcNMTIwOTEyMjE1MjAyWhcNMTUwOTEyMjE1MjAyWjBF
	MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
	ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANLJ
	hPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wok/4xIA+ui35/MmNa
	rtNuC+BdZ1tMuVCPFZcCAwEAAaNQME4wHQYDVR0OBBYEFJvKs8RfJaXTH08W+SGv
	zQyKn0H8MB8GA1UdIwQYMBaAFJvKs8RfJaXTH08W+SGvzQyKn0H8MAwGA1UdEwQF
	MAMBAf8wDQYJKoZIhvcNAQEFBQADQQBJlffJHybjDGxRMqaRmDhX0+6v02TUKZsW
	r5QuVbpQhH6u+0UgcW0jp9QwpxoPTLTWGXEWBBBurxFwiCBhkQ+V
	-----END CERTIFICATE-----
	`)
}

func TestMain(m *testing.M) {
	setup()
	tests := m.Run()
	os.Exit(tests)
}

func Test_RATLSVerifyDer_Certificate(t *testing.T) {
	t.Run("it should verify certificate with empty measurement args", func(t *testing.T) {
		err := RATLSVerifyDer(certDer, nil, nil, nil, nil)
		assert.Nil(t, err)
	})
}

func Test_RATLSVerifyDer_CertificateWithMeasurements(t *testing.T) {
	tests := []struct {
		name        string
		mrenclave   []byte
		mrsigner    []byte
		isv_prod_id []byte
		isv_svn     []byte
	}{
		{
			name:        "it should verify mrenclave value",
			mrenclave:   mrenclave,
			mrsigner:    nil,
			isv_prod_id: nil,
			isv_svn:     nil,
		},
		{
			name:        "it should verify mrsigner value",
			mrenclave:   nil,
			mrsigner:    mrsigner,
			isv_prod_id: nil,
			isv_svn:     nil,
		},
		{
			name:        "it should verify isv_prod_id value",
			mrenclave:   nil,
			mrsigner:    nil,
			isv_prod_id: isv_prod_id,
			isv_svn:     nil,
		},
		{
			name:        "it should verify isv_svn value",
			mrenclave:   nil,
			mrsigner:    nil,
			isv_prod_id: nil,
			isv_svn:     isv_svn,
		},
		{
			name:        "it should verify all measurement args",
			mrenclave:   mrenclave,
			mrsigner:    mrsigner,
			isv_prod_id: isv_prod_id,
			isv_svn:     isv_svn,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RATLSVerifyDer(certDer, tt.mrenclave, tt.mrsigner, tt.isv_prod_id, tt.isv_svn)
			assert.Nil(t, err)
		})
	}
}

func Test_RATLSVerifyDer_IncorrectMeasurements(t *testing.T) {
	tests := []struct {
		name        string
		mrenclave   []byte
		mrsigner    []byte
		isv_prod_id []byte
		isv_svn     []byte
	}{
		{
			name:        "it should throw Certificate verfication failed error due to wrong measurements",
			mrenclave:   []byte{1, 2},
			mrsigner:    nil,
			isv_prod_id: nil,
			isv_svn:     nil,
		},
		{
			name:        "it should throw Certificate verfication failed error due to wrong measurements",
			mrenclave:   nil,
			mrsigner:    []byte{1, 2},
			isv_prod_id: nil,
			isv_svn:     nil,
		},
		{
			name:        "it should throw Certificate verfication failed error due to wrong measurements",
			mrenclave:   nil,
			mrsigner:    nil,
			isv_prod_id: []byte{1, 2},
			isv_svn:     nil,
		},
		{
			name:        "it should throw Certificate verfication failed error due to wrong measurements",
			mrenclave:   nil,
			mrsigner:    nil,
			isv_prod_id: nil,
			isv_svn:     []byte{1, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RATLSVerifyDer(certDer, tt.mrenclave, tt.mrsigner, tt.isv_prod_id, tt.isv_svn)
			assert.Equal(t, err, MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
		})
	}
}

func Test_RATLSVerifyDer_IncorrectCertificate(t *testing.T) {
	tests := []struct {
		cert []byte
	}{
		{
			cert: nil,
		},
		{
			cert: []byte{1, 2},
		},
	}
	for _, tt := range tests {
		t.Run("it should invalid format error", func(t *testing.T) {
			err := RATLSVerifyDer(tt.cert, nil, nil, nil, nil)
			assert.Equal(t, err, MBEDTLS_ERR_X509_INVALID_FORMAT)
		})
	}
}

func Test_RATLSVerifyDer_MockCertificate(t *testing.T) {
	tests := []struct {
		cert []byte
	}{
		{
			cert: MockDERCertificate(),
		},
	}

	for _, tt := range tests {
		t.Run("it should invalid extension error", func(t *testing.T) {
			err := RATLSVerifyDer(tt.cert, nil, nil, nil, nil)
			assert.Equal(t, err, MBEDTLS_ERR_X509_INVALID_EXTENSIONS)
		})
	}
}

func Test_RATLSVerify_Certificate(t *testing.T) {
	err := RATLSVerify(certPem, nil, nil, nil, nil)
	assert.Nil(t, err)
}

func Test_RATLSVerify_CertificateWithMeasurements(t *testing.T) {
	err := RATLSVerify(certPem, mrenclave, mrsigner, isv_prod_id, isv_svn)
	assert.Nil(t, err)
}

func Test_RATLSVerify_NoCertificate(t *testing.T) {
	err := RATLSVerify(nil, nil, nil, nil, nil)
	assert.Equal(t, err.Error(), "empty PEM certificate")
}

func Test_RATLSVerify_InvalidCertificate(t *testing.T) {
	err := RATLSVerify(MockPEMCertificate(), nil, nil, nil, nil)
	assert.Equal(t, err.Error(), "failed to decode PEM data")
}
