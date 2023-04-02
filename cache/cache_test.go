package cache

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	cache *Cache
	cert  []byte
)

func setup() {
	// Set DEBUG flag for logs
	os.Setenv("DEBUG", "1")

	certFile, err := os.ReadFile("../test/tls/tlscert.der")
	if err != nil {
		panic("error in opening file")
	}
	cert = certFile
}

func TestMain(m *testing.M) {
	setup()
	tests := m.Run()
	os.Exit(tests)
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

func Test_NewCache(t *testing.T) {
	cache = NewCache(time.Hour, true)
	assert.NotNil(t, cache)
}

func Test_Add(t *testing.T) {
	cache = NewCache(time.Hour, true)

	err := cache.Add(cert, 0)
	assert.Nil(t, err)
}

func Test_Read(t *testing.T) {
	cache = NewCache(time.Hour, true)

	cache.Add(cert, 0)

	ret, err := cache.Read(cert)

	assert.Nil(t, err)
	assert.Equal(t, 0, ret)
}

func Test_AddItems(t *testing.T) {
	cache = NewCache(time.Hour, true)

	cert1 := MockDERCertificate()
	cert2 := MockDERCertificate()

	certs := [][]byte{cert1, cert2, cert}
	cache.AddItems(certs)

	ret, err := cache.Read(cert)
	assert.Nil(t, err)
	assert.Equal(t, 0, ret)

	ret, err = cache.Read(cert1)
	assert.Nil(t, err)
	assert.Equal(t, 0, ret)
}

func Test_Evict(t *testing.T) {
	cache = NewCache(2*time.Second, true)

	cert1 := MockDERCertificate()
	cert2 := MockDERCertificate()

	cache.Add(cert1, -1)

	time.Sleep(4 * time.Second)

	cache.Add(cert2, -1)

	ret, err := cache.Read(cert1)
	assert.NotNil(t, err)
	assert.Equal(t, math.MinInt32, ret)

	ret, err = cache.Read(cert2)
	assert.Nil(t, err)
	assert.Equal(t, -1, ret)
}

func Test_IsEnabled(t *testing.T) {
	cache = NewCache(time.Hour, false)

	assert.False(t, cache.IsEnabled())

	err := cache.Add(cert, 0)
	assert.NotNil(t, err)
}

func Test_Toggle(t *testing.T) {
	cache = NewCache(time.Hour, true)

	assert.True(t, cache.IsEnabled())

	cache.Toggle()

	assert.False(t, cache.IsEnabled())
}
