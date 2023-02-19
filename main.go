package main

// #cgo LDFLAGS: -ldl
// #include <assert.h>
// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdbool.h>
// #include <string.h>
//
// /* expected SGX measurements in binary form */
// char g_expected_mrenclave[32];
// char g_expected_mrsigner[32];
// char g_expected_isv_prod_id[2];
// char g_expected_isv_svn[2];
//
// bool g_verify_mrenclave   = false;
// bool g_verify_mrsigner    = false;
// bool g_verify_isv_prod_id = false;
// bool g_verify_isv_svn     = false;
//
// /* RA-TLS: our own callback to verify SGX measurements */
// int my_verify_measurements(const char* mrenclave, const char* mrsigner,
//                                   const char* isv_prod_id, const char* isv_svn) {
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
import "C"

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"unsafe"
)

func RATLSVerifyDer(certDER, mrenclave, mrsigner, isv_prod_id, isv_svn []byte) error {
	helper_sgx_urts_lib_name := "libsgx_urts.so"
	helper_sgx_urts_lib_sym := C.CString("libsgx_urts.so")
	defer C.free(unsafe.Pointer(helper_sgx_urts_lib_sym))
	helper_sgx_urts_lib := C.dlopen(helper_sgx_urts_lib_sym, C.RTLD_LAZY)
	if helper_sgx_urts_lib == nil {
		return fmt.Errorf("error opening %q", helper_sgx_urts_lib_name)
	}
	defer func() {
		if r := C.dlclose(helper_sgx_urts_lib); r != 0 {
			_ = fmt.Errorf("error closing %q", helper_sgx_urts_lib_name)
		}
	}()

	ra_tls_verify_lib_name := "libra_tls_verify_dcap.so"
	ra_tls_verify_lib_sym := C.CString(ra_tls_verify_lib_name)
	defer C.free(unsafe.Pointer(ra_tls_verify_lib_sym))
	ra_tls_verify_lib := C.dlopen(ra_tls_verify_lib_sym, C.RTLD_LAZY)
	if ra_tls_verify_lib == nil {
		return fmt.Errorf("error opening %q", ra_tls_verify_lib_name)
	}
	defer func() {
		if r := C.dlclose(ra_tls_verify_lib); r != 0 {
			_ = fmt.Errorf("error closing %q", ra_tls_verify_lib_name)
		}
	}()

	ra_tls_verify_callback_der_name := "ra_tls_verify_callback_der"
	ra_tls_verify_callback_der_sym := C.CString(ra_tls_verify_callback_der_name)
	defer C.free(unsafe.Pointer(ra_tls_verify_callback_der_sym))
	ra_tls_verify_callback_der_f := C.dlsym(ra_tls_verify_lib, ra_tls_verify_callback_der_sym)
	if ra_tls_verify_callback_der_f == nil {
		return fmt.Errorf("error resolving %q function", ra_tls_verify_callback_der_name)
	}

	ra_tls_set_measurement_callback := "ra_tls_set_measurement_callback"
	ra_tls_set_measurement_callback_sym := C.CString(ra_tls_set_measurement_callback)
	defer C.free(unsafe.Pointer(ra_tls_set_measurement_callback_sym))
	ra_tls_set_measurement_callback_f := C.dlsym(ra_tls_verify_lib, ra_tls_set_measurement_callback_sym)
	if ra_tls_set_measurement_callback_f == nil {
		return fmt.Errorf("error resolving %q function", ra_tls_set_measurement_callback)
	}

	// set verify callback
	C.ra_tls_set_measurement_callback_wrapper(ra_tls_set_measurement_callback_f)

	// check for null for each measurement verification
	if len(mrenclave) == 0 {
		C.g_verify_mrenclave = false
	} else {
		C.g_verify_mrenclave = true
		C.memcpy(unsafe.Pointer(&(C.g_expected_mrenclave[0])), unsafe.Pointer(&mrenclave[0]), C.size_t(len(mrenclave)))
	}

	if len(mrsigner) == 0 {
		C.g_verify_mrsigner = false
	} else {
		C.g_verify_mrsigner = true
		C.memcpy(unsafe.Pointer(&(C.g_expected_mrsigner[0])), unsafe.Pointer(&mrsigner[0]), C.size_t(len(mrsigner)))
	}

	if len(isv_prod_id) == 0 {
		C.g_verify_isv_prod_id = false
	} else {
		C.g_verify_isv_prod_id = true
		C.memcpy(unsafe.Pointer(&(C.g_expected_isv_prod_id[0])), unsafe.Pointer(&isv_prod_id[0]), C.size_t(len(isv_prod_id)))
	}

	if len(isv_svn) == 0 {
		C.g_verify_isv_svn = false
	} else {
		C.g_verify_isv_svn = true
		C.memcpy(unsafe.Pointer(&(C.g_expected_isv_svn[0])), unsafe.Pointer(&isv_svn[0]), C.size_t(len(isv_svn)))
	}

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

// func main() {

// 	helper_sgx_urts_lib_name := C.CString("libsgx_urts.so")
// 	defer C.free(unsafe.Pointer(helper_sgx_urts_lib_name))
// 	helper_sgx_urts_lib := C.dlopen(helper_sgx_urts_lib_name, C.RTLD_LAZY)
// 	if helper_sgx_urts_lib == nil {
// 		fmt.Errorf("error opening %q", helper_sgx_urts_lib_name)
// 		return
// 	}
// 	defer func() {
// 		if r := C.dlclose(helper_sgx_urts_lib); r != 0 {
// 			fmt.Errorf("error closing %q", helper_sgx_urts_lib_name)
// 		}
// 	}()

// 	ra_tls_verify_lib_name := C.CString("libra_tls_verify_dcap.so")
// 	defer C.free(unsafe.Pointer(ra_tls_verify_lib_name))
// 	ra_tls_verify_lib := C.dlopen(ra_tls_verify_lib_name, C.RTLD_LAZY)
// 	if ra_tls_verify_lib == nil {
// 		fmt.Errorf("error opening %q", ra_tls_verify_lib_name)
// 		return
// 	}
// 	defer func() {
// 		if r := C.dlclose(ra_tls_verify_lib); r != 0 {
// 			fmt.Errorf("error closing %q", ra_tls_verify_lib_name)
// 		}
// 	}()

// 	ra_tls_verify_callback_der_sym := C.CString("ra_tls_verify_callback_der")
// 	defer C.free(unsafe.Pointer(ra_tls_verify_callback_der_sym))
// 	ra_tls_verify_callback_der_f := C.dlsym(ra_tls_verify_lib, ra_tls_verify_callback_der_sym)
// 	if ra_tls_verify_callback_der_f == nil {
// 		fmt.Errorf("error resolving %q function", ra_tls_verify_callback_der_sym)
// 		return
// 	}

// 	ra_tls_set_measurement_callback_sym := C.CString("ra_tls_set_measurement_callback")
// 	defer C.free(unsafe.Pointer(ra_tls_set_measurement_callback_sym))
// 	ra_tls_set_measurement_callback_f := C.dlsym(ra_tls_verify_lib, ra_tls_set_measurement_callback_sym)
// 	if ra_tls_set_measurement_callback_f == nil {
// 		fmt.Errorf("error resolving %q function", ra_tls_set_measurement_callback_sym)
// 		return
// 	}

// 	C.ra_tls_set_measurement_callback_wrapper(ra_tls_set_measurement_callback_f)

// 	certFile := "tls/tlscert.der"
// 	certDER, err := os.ReadFile(certFile)

// 	if err != nil {
// 	}

// 	cert_size := C.size_t(len(certDER))
// 	certDER_sym := C.CBytes(certDER)
// 	defer C.free(unsafe.Pointer(certDER_sym))
// 	fmt.Println(certDER_sym, ra_tls_set_measurement_callback_f)
// 	ret := C.ra_tls_verify_callback_der_wrapper(ra_tls_verify_callback_der_f, (*C.uchar)(certDER_sym), cert_size)

// 	// convert der cert to C objects
// 	// copy attestation consumables to static c objects
// 	// call measurement callback

// 	fmt.Println("Success: ", ret)

// 	/*
// 		var s string
// 		sl := C.CString(s)
// 		defer C.free(unsafe.Pointer(sl))

// 		ret := C.my_sd_pid_get_slice(sd_pid_get_slice, 0, &sl)
// 		if ret < 0 {
// 			err = fmt.Errorf("error calling sd_pid_get_slice: %v", syscall.Errno(-ret))
// 			return
// 		}

// 		slice = C.GoString(sl)
// 	*/
// 	return
// }
