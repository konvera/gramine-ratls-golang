// Error codes are standard MBEDTLS error code found here:
// https://github.com/Mbed-TLS/mbedtls/blob/development/include/mbedtls/x509.h
package gramine_ratls

import (
	"fmt"
)

type ErrorCode int

const (
	// Fatal error occured, not able to load RATLS libraries
	RATLS_WRAPPER_ERR_LIB_LOAD_FAILED ErrorCode = -0x0001

	// Invalid path
	RATLS_WRAPPER_ERR_PATH_INVALID ErrorCode = -0x0002

	// Invalid arguments, e.g. certificate is empty
	RATLS_WRAPPER_ERR_INVALID_ARGS ErrorCode = -0x0003

	// Certificate creation failed
	RATLS_WRAPPER_ERR_CERTIFICATE_CREATION_FAILED ErrorCode = -0x0004

	// Invalid SGX Attestation file
	RATLS_WRAPPER_ERR_SGX_ATTESTATION_FILE ErrorCode = -0x0005

	// Invalid certificate
	RATLS_WRAPPER_ERR_INVALID_CERT ErrorCode = -0x0006

	// Certificate decoding failed
	RATLS_WRAPPER_ERR_CERT_DECODE_FAILED ErrorCode = -0x0007

	// Cache not enabled
	CACHE_ERR_NOT_ENABLED ErrorCode = -0x0008

	// Entropy Source Failed
	MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED ErrorCode = -0x0034

	// The CRT/CRL/CSR format is invalid, e.g. different type expected.
	MBEDTLS_ERR_X509_INVALID_FORMAT ErrorCode = -0x2180

	// The extension tag or value is invalid.
	MBEDTLS_ERR_X509_INVALID_EXTENSIONS ErrorCode = -0x2500

	// Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid)
	MBEDTLS_ERR_X509_SIG_MISMATCH ErrorCode = -0x2680

	// Certificate verification failed, e.g. CRL, CA or signature check failed.
	MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ErrorCode = -0x2700

	// Allocation of memory failed.
	MBEDTLS_ERR_X509_ALLOC_FAILED ErrorCode = -0x2880

	// A fatal error occurred, eg the chain is too long or the vrfy callback failed.
	MBEDTLS_ERR_X509_FATAL_ERROR ErrorCode = -0x3000

	// Bad input parameters to function.
	MBEDTLS_ERR_PK_BAD_INPUT_DATA ErrorCode = -0x3E80

	// Memory Allocation Failed
	MBEDTLS_ERR_PK_ALLOC_FAILED ErrorCode = -0x3F80
)

// Message returns the status code message
func (o ErrorCode) Error() string {
	switch o {
	case RATLS_WRAPPER_ERR_LIB_LOAD_FAILED:
		return fmt.Sprintf("RATLS library loading failed: %d", o)

	case RATLS_WRAPPER_ERR_PATH_INVALID:
		return fmt.Sprintf("Invalid path format: %d", o)

	case RATLS_WRAPPER_ERR_INVALID_ARGS:
		return fmt.Sprintf("Invalid args: %d", o)

	case RATLS_WRAPPER_ERR_CERTIFICATE_CREATION_FAILED:
		return fmt.Sprintf("Certificate creation failed: %d", o)

	case RATLS_WRAPPER_ERR_SGX_ATTESTATION_FILE:
		return fmt.Sprintf("SGX RA-TLS attestation type file '/dev/attestation/attestation_type' not found: %d", o)

	case RATLS_WRAPPER_ERR_INVALID_CERT:
		return fmt.Sprintf("Invalid certificate: %d", o)

	case RATLS_WRAPPER_ERR_CERT_DECODE_FAILED:
		return fmt.Sprintf("failed to decode PEM certificate: %d", o)

	case CACHE_ERR_NOT_ENABLED:
		return fmt.Sprintf("cache not enabled: %d", o)

	case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
		return fmt.Sprintf("Entropy Source Failed: %d", o)

	case MBEDTLS_ERR_X509_INVALID_FORMAT:
		return fmt.Sprintf("The CRT/CRL/CSR format is invalid: %d", o)

	case MBEDTLS_ERR_X509_INVALID_EXTENSIONS:
		return fmt.Sprintf("The extension tag or value is invalid: %d", o)

	case MBEDTLS_ERR_X509_SIG_MISMATCH:
		return fmt.Sprintf("Signature algorithms do not match: %d", o)

	case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
		return fmt.Sprintf("Certificate verification failed: %d", o)

	case MBEDTLS_ERR_X509_ALLOC_FAILED:
		return fmt.Sprintf("Allocation of memory failed: %d", o)

	case MBEDTLS_ERR_X509_FATAL_ERROR:
		return fmt.Sprintf("A fatal error occurred: %d", o)

	case MBEDTLS_ERR_PK_BAD_INPUT_DATA:
		return fmt.Sprintf("Bad input parameters to function: %d", o)

	case MBEDTLS_ERR_PK_ALLOC_FAILED:
		return fmt.Sprintf("Memory Allocation Failed: %d", o)

	default:
		return fmt.Sprintf("UNKNOWN: %d", o)
	}
}
