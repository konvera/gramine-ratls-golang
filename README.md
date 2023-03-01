# Gramine-RATLS-Wrapper

Gramine-RATLS-Wrapper is a Go wrapper on top of the [Gramine](https://github.com/gramineproject/gramine) [Remote Attestation TLS](https://github.com/gramineproject/gramine/tree/master/tools/sgx/ra-tls) (RATLS) library. Forwards the certificate and SGX quote to the DCAP verification service. It also verifies SGX specific measurement variables that are used to verify the identity of the enclave, namely:

1. `MRENCLAVE`: hex string that verifes attesting enclave.
2. `MRSIGNER`: hex string that verifies the key used to sign the enclave.
3. `ISV_PROD_ID`: decimal string that verifes the valid product ID.
4. `ISV_SVN`: decimal string metadata variable that specifes valid version number.

More info about the core library can be found at the official gramine [docs](https://github.com/gramineproject/gramine).

## Functions

The wrapper provides two functions for verifying RATLS certificates:

### RATLSVerifyDer

```go
func RATLSVerifyDer(cert, mrenclave, mrsigner, isv_prod_id, isv_svn []byte) error
```

RATLSVerifyDer verifies a DER-encoded RATLS certificate using the given `mrenclave`, `mrsigner`, `isv_prod_id`, and `isv_svn`. If the certificate is valid, this function returns `nil`. If the certificate is invalid, this function returns an error describing the validation failure.

### RATLSVerify

```go
func RATLSVerify(cert, mrenclave, mrsigner, isv_prod_id, isv_svn []byte) error
```

RATLSVerify verifies a PEM-encoded RATLS certificate using the given SGX measurement args.

## Installation

To use RATLSWrapper, you must have Go installed on your system. You can then install RATLSWrapper using the following command:

```bash
go get github.com/konvera/gramine-ratls-golang
```

## Usage

To use RA-TLS wrapper, import the `gramine_ratls` package and call the RATLSVerifyDer or RATLSVerify functions depending on the certificate:

```go
func main() {
	// Assume that we have a RATLS certificate in a byte slice called "cert"
	// Assume that we have the mrenclave, mrsigner, isv_prod_id, and isv_svn values in byte slices
	err := gramine_ratls.RATLSVerifyDer(cert, mrenclave, mrsigner, isv_prod_id, isv_svn)
	if err != nil {
		fmt.Printf("Certificate verification failed: %v\n", err)
	} else {
		fmt.Println("Certificate verified successfully.")
	}
}
```

In this example, we assume that we have a RATLS certificate in a byte slice called `cert`, and that we have the `mrenclave`, `mrsigner`, `isv_prod_id`, and `isv_svn` values in byte slices. We call the `RATLSVerifyDer` function to verify the certificate. If verification fails, we print an error message. If verification succeeds, we print a success message.

Similarly, we can call the `RATLSVerify` function to verify a PEM-encoded RATLS certificate. Note that in both cases, the `cert` parameter must be a DER-encoded or PEM-encoded RATLS certificate, depending on which function is being called.

> Note that enclave measurement arguments can be optional depending on the measurement callback defined as per usage.

More info about examples and usage can be found at the [tests](./gramine_ratls_test.go) defined in the repository.