// Error codes are standard MBEDTLS error code found here:
// https://github.com/Mbed-TLS/mbedtls/blob/development/include/mbedtls/x509.h
package gramine_ratls

import (
	"fmt"
)

type ErrorCode int

const (
	// The CRT/CRL/CSR format is invalid, e.g. different type expected.
	MBEDTLS_ERR_X509_INVALID_FORMAT ErrorCode = -0x2180

	// Certificate verification failed, e.g. CRL, CA or signature check failed.
	MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ErrorCode = -0x2700

	// The extension tag or value is invalid.
	MBEDTLS_ERR_X509_INVALID_EXTENSIONS ErrorCode = -0x2500

	// Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid)
	MBEDTLS_ERR_X509_SIG_MISMATCH ErrorCode = -0x2680

	// A fatal error occurred, eg the chain is too long or the vrfy callback failed.
	MBEDTLS_ERR_X509_FATAL_ERROR ErrorCode = -0x3000

	// Allocation of memory failed.
	MBEDTLS_ERR_X509_ALLOC_FAILED ErrorCode = -0x2880

	// Entropy Source Failed
	MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED ErrorCode = -0x0034

	// Bad input parameters to function.
	MBEDTLS_ERR_PK_BAD_INPUT_DATA ErrorCode = -0x3E80

	// Memory Allocation Failed
	MBEDTLS_ERR_PK_ALLOC_FAILED ErrorCode = -0x3F80
)

// Message returns the status code message
func (o ErrorCode) Error() string {
	switch o {
	case -0x2700:
		return fmt.Sprintf("Certificate verification failed: %d", o)

	case -0x2180:
		return fmt.Sprintf("The CRT/CRL/CSR format is invalid: %d", o)

	case -0x2500:
		return fmt.Sprintf("The extension tag or value is invalid: %d", o)

	case -0x2680:
		return fmt.Sprintf("Signature algorithms do not match: %d", o)

	case -0x3000:
		return fmt.Sprintf("A fatal error occurred: %d", o)

	case -0x2880:
		return fmt.Sprintf("Allocation of memory failed: %d", o)

	default:
		return fmt.Sprintf("UNKNOWN: %d", o)
	}
}
