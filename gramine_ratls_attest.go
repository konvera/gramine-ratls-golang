package gramine_ratls

// #cgo LDFLAGS: -ldl
// #include <assert.h>
// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <string.h>
// #include <stdio.h>
//
// int ra_tls_create_key_and_crt_der_wrapper(void* f, u_int8_t** der_key, size_t* der_key_size, u_int8_t** der_crt, size_t* der_crt_size) {
//      int ( * ra_tls_create_key_and_crt_der)(u_int8_t**, size_t*, u_int8_t**, size_t*);
//      ra_tls_create_key_and_crt_der = (int (*)(u_int8_t**, size_t*, u_int8_t**, size_t*)) f;
//      return ra_tls_create_key_and_crt_der(der_key, der_key_size, der_crt, der_crt_size);
// }
import "C"

import (
	"os"
	"unsafe"
)

func getAttestationType() (string, error) {
	attestationType, err := os.ReadFile("/dev/attestation/attestation_type")
	if err != nil {
		PrintDebug("SGX RA-TLS attestation type file '/dev/attestation/attestation_type' not found")
		return "", RATLS_WRAPPER_ERR_SGX_ATTESTATION_FILE
	}

	return string(attestationType), nil
}

func RATLSCreateKeyAndCrtDer(keyPath string, crtPath string) error {
	if ra_tls_attest_create_key_and_crt_der_callback_f == nil {
		PrintDebug("RA-TLS attest libraries not linked.")
		return RATLS_WRAPPER_ERR_LIB_LOAD_FAILED
	}

	attestationType, err := getAttestationType()
	if err != nil {
		return err
	}

	switch attestationType {
	case "none":
		PrintDebug("Skipping certificate creation. Remote attestation type: ", attestationType)
		return RATLS_WRAPPER_ERR_CERTIFICATE_CREATION_FAILED
	case "dcap":
		var derCrt *C.uchar
		var crtLen C.size_t
		var derKey *C.uchar
		var keyLen C.size_t

		ret := C.ra_tls_create_key_and_crt_der_wrapper(ra_tls_attest_create_key_and_crt_der_callback_f, &derKey, &keyLen, &derCrt, &crtLen)

		if ret != 0 {
			PrintDebug("RATLSCreateKeyAndCrtDer failed with error ", ret)
			// TODO: custom error type for ret
			return ErrorCode(ret)
		}

		f, err := os.Create(crtPath)
		if err != nil {
			PrintDebug("error creating DER Certificate ", err)
			return err
		}
		defer f.Close()

		g, err := os.Create(keyPath)
		if err != nil {
			PrintDebug("error creating DER Key ", err)
			return err
		}
		defer g.Close()

		derCrtBytes := C.GoBytes(unsafe.Pointer(derCrt), C.int(crtLen))
		_, err = f.Write(derCrtBytes)

		if err != nil {
			PrintDebug("error while writing Cert ", err)
			return err
		}

		derKeyBytes := C.GoBytes(unsafe.Pointer(derKey), C.int(keyLen))
		_, err = g.Write(derKeyBytes)

		if err != nil {
			PrintDebug("error while writing key ", err)
			return err
		}

		PrintDebug("Certificate and key creation succeded.")
	default:
		PrintDebug("Certifiate creation with mentioned attestation type not supported.")
		return RATLS_WRAPPER_ERR_CERTIFICATE_CREATION_FAILED
	}

	return nil
}
