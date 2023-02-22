package main

// #cgo LDFLAGS: -ldl
// #include <assert.h>
// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <string.h>
// #include <stdio.h>
//
// /* expected SGX measurements in binary form */
// static char g_expected_mrenclave[32];
// static char g_expected_mrsigner[32];
// char g_expected_isv_prod_id[2];
// char g_expected_isv_svn[2];
//
// static bool g_verify_mrenclave   = false;
// static bool g_verify_mrsigner    = false;
// static bool g_verify_isv_prod_id = false;
// static bool g_verify_isv_svn     = false;
//
// /* RA-TLS: our own callback to verify SGX measurements */
// int my_verify_measurements(const char* mrenclave, const char* mrsigner,
//                                   const char* isv_prod_id, const char* isv_svn) {
//     printf("%s\n", mrsigner);
//     assert(mrenclave && mrsigner && isv_prod_id && isv_svn);
//
//     if (g_verify_mrenclave &&
//             memcmp(mrenclave, g_expected_mrenclave, sizeof(g_expected_mrenclave)))
//         return -1;
//
//     if (g_verify_mrsigner &&
//             memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner)))
//         return -1;
//
//     if (g_verify_isv_prod_id &&
//             memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)))
//         return -1;
//
//     if (g_verify_isv_svn &&
//             memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn)))
//         return -1;
//
//     return 0;
// }
//
// int ra_tls_verify_callback_der_wrapper(void *f, u_int8_t* der_crt, size_t der_crt_size) {
//
//     int (*ra_tls_verify_callback_der)(u_int8_t*, size_t);
//     ra_tls_verify_callback_der = (int (*)(u_int8_t*, size_t))f;
//     return ra_tls_verify_callback_der(der_crt,der_crt_size);
// }
//
// void ra_tls_set_measurement_callback_wrapper(void *f) {
//     void (*ra_tls_set_measurement_callback)(int (*)(const char*, const char*, const char*, const char*));
//     ra_tls_set_measurement_callback = (void (*)(int (*)(const char*, const char*, const char*, const char*)))f;
//     ra_tls_set_measurement_callback(my_verify_measurements);
// }
//
// void set_g_verify_mrenclave(bool val) {
//	g_verify_mrenclave = val;
// }
//
// void set_g_verify_mrsigner(bool val) {
// 	g_verify_mrsigner = val;
// }
//
// void set_g_verify_isv_prod_id(bool val) {
// 	g_verify_isv_prod_id = val;
// }
//
// void set_g_verify_isv_svn(bool val) {
// 	g_verify_isv_svn = val;
// }
//
// void set_g_expected(void* dest, void* src, size_t size) {
//	memcpy(dest, src, size);
// }
//
// void set_g_expected_mrenclave(void* src, size_t size) {
// 	memcpy(g_expected_mrenclave, src, size);
// }
//
// void set_g_expected_mrsigner(void* src, size_t size) {
// 	memcpy(g_expected_mrsigner, src, size);
// }
//
// void set_g_expected_isv_prod_id(void* src, size_t size) {
// 	memcpy(g_expected_isv_prod_id, src, size);
// }
//
// void set_g_expected_isv_svn(void* src, size_t size) {
// 	memcpy(g_expected_isv_svn, src, size);
// }
import "C"

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"unsafe"
)

var ra_tls_verify_callback_der_f unsafe.Pointer
var ra_tls_set_measurement_callback_f unsafe.Pointer

func init() {
	helper_sgx_urts_lib_name := "libsgx_urts.so"
	helper_sgx_urts_lib_sym := C.CString("libsgx_urts.so")
	defer C.free(unsafe.Pointer(helper_sgx_urts_lib_sym))
	helper_sgx_urts_lib := C.dlopen(helper_sgx_urts_lib_sym, C.RTLD_LAZY)
	if helper_sgx_urts_lib == nil {
		panic(fmt.Errorf("error opening %q", helper_sgx_urts_lib_name))
	}

	ra_tls_verify_lib_name := "libra_tls_verify_dcap.so"
	ra_tls_verify_lib_sym := C.CString(ra_tls_verify_lib_name)
	defer C.free(unsafe.Pointer(ra_tls_verify_lib_sym))
	ra_tls_verify_lib := C.dlopen(ra_tls_verify_lib_sym, C.RTLD_LAZY)
	if ra_tls_verify_lib == nil {
		panic(fmt.Errorf("error opening %q", ra_tls_verify_lib_name))
	}

	ra_tls_verify_callback_der_name := "ra_tls_verify_callback_der"
	ra_tls_verify_callback_der_sym := C.CString(ra_tls_verify_callback_der_name)
	defer C.free(unsafe.Pointer(ra_tls_verify_callback_der_sym))
	ra_tls_verify_callback_der_f = C.dlsym(ra_tls_verify_lib, ra_tls_verify_callback_der_sym)
	if ra_tls_verify_callback_der_f == nil {
		panic(fmt.Errorf("error resolving %q function", ra_tls_verify_callback_der_name))
	}

	ra_tls_set_measurement_callback := "ra_tls_set_measurement_callback"
	ra_tls_set_measurement_callback_sym := C.CString(ra_tls_set_measurement_callback)
	defer C.free(unsafe.Pointer(ra_tls_set_measurement_callback_sym))
	ra_tls_set_measurement_callback_f = C.dlsym(ra_tls_verify_lib, ra_tls_set_measurement_callback_sym)
	if ra_tls_set_measurement_callback_f == nil {
		panic(fmt.Errorf("error resolving %q function", ra_tls_set_measurement_callback))
	}
}

func set_measurement_verification_args(mrenclave, mrsigner, isv_prod_id, isv_svn []byte) {
	if len(mrenclave) == 0 {
		C.set_g_verify_mrenclave(false)
	} else {
		C.set_g_verify_mrenclave(true)
		C.set_g_expected_mrenclave(unsafe.Pointer(&mrenclave[0]), C.size_t(len(mrenclave)))
	}

	if len(mrsigner) == 0 {
		C.set_g_verify_mrsigner(false)
	} else {
		C.set_g_verify_mrsigner(true)
		C.set_g_expected_mrsigner(unsafe.Pointer(&mrsigner[0]), C.size_t(len(mrsigner)))
	}

	if len(isv_prod_id) == 0 {
		C.set_g_verify_isv_prod_id(false)
	} else {
		C.set_g_verify_isv_prod_id(true)
		C.set_g_expected_isv_prod_id(unsafe.Pointer(&isv_prod_id[0]), C.size_t(len(isv_prod_id)))
	}

	if len(isv_svn) == 0 {
		C.set_g_verify_isv_svn(false)
	} else {
		C.set_g_verify_isv_svn(true)
		C.set_g_expected_isv_svn(unsafe.Pointer(&isv_svn[0]), C.size_t(len(isv_svn)))
	}
}

func RATLSVerifyDer(certDER, mrenclave, mrsigner, isv_prod_id, isv_svn []byte) error {
	// set verify callback
	C.ra_tls_set_measurement_callback_wrapper(ra_tls_set_measurement_callback_f)

	// check for null for each measurement verification
	set_measurement_verification_args(mrenclave, mrsigner, isv_prod_id, isv_svn)

	cert_size := C.size_t(len(certDER))
	certDER_sym := C.CBytes(certDER)
	defer C.free(unsafe.Pointer(certDER_sym))

	ret := C.ra_tls_verify_callback_der_wrapper(ra_tls_verify_callback_der_f, (*C.uchar)(certDER_sym), cert_size)

	fmt.Println("Success: ", ret)
	if ret != 0 {
		return errors.New("error in verifying cert")
	}

	return nil
}

func RATLSVerify(cert, mrenclave, mrsigner, isv_prod_id, isv_svn []byte) error {
	if len(cert) == 0 {
		return errors.New("empty CERT")
	}

	block, _ := pem.Decode(cert)
	if block == nil {
		return errors.New("failed to decode PEM data")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("failed to create cert")
	}

	return RATLSVerifyDer(certificate.Raw, mrenclave, mrsigner, isv_prod_id, isv_svn)
}

func main() {
	certFile, err := os.ReadFile("tls/tlscert.der")
	if err != nil {
		panic("error in opening cert file")
	}

	RATLSVerifyDer(certFile, nil, nil, nil, nil)
}
