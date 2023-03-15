package gramine_ratls

// #cgo LDFLAGS: -ldl
// #include <assert.h>
// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <string.h>
// #include <stdio.h>
//
// int ra_tls_create_key_and_crt_der_wrapper(void* f, u_int8_t** der_crt, size_t* der_crt_size, u_int8_t** der_key, size_t* der_key_size) {
//      int ( * ra_tls_create_key_and_crt_der)(u_int8_t**, size_t*, u_int8_t**, size_t*);
//      ra_tls_create_key_and_crt_der = (int (*)(u_int8_t**, size_t*, u_int8_t**, size_t*)) f;
//      return ra_tls_create_key_and_crt_der(der_crt, der_crt_size, der_key, der_key_size);
// }
import "C"

import (
	"errors"
	"fmt"
	"log"
	"os"
	"unsafe"
)

var ra_tls_attest_create_key_and_crt_der_callback_f unsafe.Pointer

func LoadRATLSAttestLibs() {
	ra_tls_attest_lib_name := "libra_tls_attest.so"
	ra_tls_attest_lib_sym := C.CString(ra_tls_attest_lib_name)
	defer C.free(unsafe.Pointer(ra_tls_attest_lib_sym))
	ra_tls_attest_lib := C.dlopen(ra_tls_attest_lib_sym, C.RTLD_LAZY)
	if ra_tls_attest_lib == nil {
		panic(fmt.Errorf("error opening %q", ra_tls_attest_lib_name))
	}

	ra_tls_attest_create_key_and_crt_name := "ra_tls_create_key_and_crt_der"
	ra_tls_attest_create_key_and_crt_sym := C.CString(ra_tls_attest_create_key_and_crt_name)
	defer C.free(unsafe.Pointer(ra_tls_attest_create_key_and_crt_sym))
	ra_tls_attest_create_key_and_crt_der_callback_f = C.dlsym(ra_tls_attest_lib, ra_tls_attest_create_key_and_crt_sym)
	if ra_tls_attest_create_key_and_crt_der_callback_f == nil {
		panic(fmt.Errorf("error resolving %q function", ra_tls_attest_create_key_and_crt_name))
	}
}

func getAttestationType() string {
	attestationType, err := os.ReadFile("/dev/attestation/attestation_type")
	if err != nil {
		log.Fatal("RA-TLS attestation type file `/dev/attestation/attestation_type` not found")
		return ""
	}

	return string(attestationType)
}

func RATLSCreateKeyAndCrtDer() error {
	if ra_tls_attest_create_key_and_crt_der_callback_f == nil {
		log.Fatal("RA-TLS Attest libraries not loaded.")
	}

	attestationType := getAttestationType()
	switch attestationType {
	case "none":
		log.Println("Skipping certificate creation. Remote attestation type: ", attestationType)
		return nil
	case "dcap":
		var derCrt *C.uchar
		var certLen C.size_t
		var derKey *C.uchar
		var derLen C.size_t

		ret := C.ra_tls_create_key_and_crt_der_wrapper(ra_tls_attest_create_key_and_crt_der_callback_f, &derCrt, &certLen, &derKey, &derLen)

		if ret != 0 {
			log.Println("RATLSCreateKeyAndCrtDer failed with error ", ret)
			// TODO: custom error type for ret
			return ErrorCode(ret)
		}

		f, err := os.Create(os.Getenv("RATLS_CRT_PATH"))
		if err != nil {
			log.Println("error creating DER Certificate ", err)
			return err
		}
		defer f.Close()

		g, err := os.Create(os.Getenv("RATLS_KEY_PATH"))
		if err != nil {
			log.Println("error creating DER Key ", err)
			return err
		}
		defer g.Close()

		derCrtBytes := C.GoBytes(unsafe.Pointer(derCrt), C.int(certLen))
		_, err = f.Write(derCrtBytes)

		if err != nil {
			log.Println("error while writing Cert ", err)
			return err
		}

		derKeyBytes := C.GoBytes(unsafe.Pointer(derKey), C.int(derLen))
		_, err = g.Write(derKeyBytes)

		if err != nil {
			log.Println("error while writing key ", err)
			return err
		}

		log.Println("Certificate and key creation succeded.")
	default:
		return errors.New("Unknown remote attestation type")
	}

	return nil
}
