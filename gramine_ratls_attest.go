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

	"github.com/konvera/gramine-ratls-golang/utils"
)

func getAttestationType() (string, error) {
	attestationType, err := os.ReadFile("/dev/attestation/attestation_type")
	if err != nil {
		utils.PrintDebug("SGX RA-TLS attestation type file '/dev/attestation/attestation_type' not found")
		return "", RATLS_WRAPPER_ERR_SGX_ATTESTATION_FILE
	}

	return string(attestationType), nil
}

func RATLSCreateKeyAndCrtDer() ([]byte, []byte, error) {
	if ra_tls_attest_create_key_and_crt_der_callback_f == nil {
		utils.PrintDebug("RA-TLS attest libraries not linked.")
		return nil, nil, RATLS_WRAPPER_ERR_LIB_LOAD_FAILED
	}

	attestationType, err := getAttestationType()
	if err != nil {
		return nil, nil, err
	}

	switch attestationType {
	case "none":
		utils.PrintDebug("Skipping certificate creation. Remote attestation type: ", attestationType)
		return nil, nil, RATLS_WRAPPER_ERR_CERTIFICATE_CREATION_FAILED
	case "dcap":
		var derCrt *C.uchar
		var crtLen C.size_t
		var derKey *C.uchar
		var keyLen C.size_t

		ret := C.ra_tls_create_key_and_crt_der_wrapper(ra_tls_attest_create_key_and_crt_der_callback_f, &derKey, &keyLen, &derCrt, &crtLen)

		if ret != 0 {
			utils.PrintDebug("RATLSCreateKeyAndCrtDer failed with error ", ret)
			return nil, nil, ErrorCode(ret)
		}

		derCrtBytes := C.GoBytes(unsafe.Pointer(derCrt), C.int(crtLen))
		derKeyBytes := C.GoBytes(unsafe.Pointer(derKey), C.int(keyLen))

		utils.PrintDebug("Certificate and key creation succeded.")
		return derKeyBytes, derCrtBytes, nil
	default:
		utils.PrintDebug("Certifiate creation with mentioned attestation type not supported.")
		return nil, nil, RATLS_WRAPPER_ERR_CERTIFICATE_CREATION_FAILED
	}
}
