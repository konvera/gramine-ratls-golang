package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var certFilePath = "tls/tlscert.der"

func Test_RATLSVerifyDer(t *testing.T) {
	certFile, err := os.ReadFile(certFilePath)
	if err != nil {
		t.Error("error in opening file")
	}

	err = RATLSVerifyDer(certFile, nil, nil, nil, nil)
	assert.Nil(t, err)
}
