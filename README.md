# Gramine-RATLS-Wrapper

Gramine-RATLS-Wrapper is a Go wrapper on top of the [Gramine](https://github.com/gramineproject/gramine) [Remote Attestation TLS](https://github.com/gramineproject/gramine/tree/master/tools/sgx/ra-tls) (RATLS) library. This wrapper provides functionality for creation of certificate and key used for Remote Attestation and Verification of the quote sent using the certificate by forwarding it to the RA verification service. It also verifies SGX specific measurement variables that are used to verify the identity of the enclave, namely:

1. `MRENCLAVE`: 32 byte hex string that verifes attesting enclave.
2. `MRSIGNER`: 32 byte hex string that verifies the key used to sign the enclave.
3. `ISV_PROD_ID`: 2 byte decimal string that verifes the valid product ID.
4. `ISV_SVN`: 2 byte decimal string metadata variable that specifes valid version number.

More info about the core library can be found at the official gramine [docs](https://gramine.readthedocs.io/en/stable/attestation.html#mid-level-ra-tls-interface).

The wrapper provides a simple in-memory cache that can be used to save successfully attested certificates to prevent the latency of TLS verification.

## Functions

### Attestation

#### RATLSCreateKeyAndCrtDer

```go
// Returns Key, Certificate, Error
func RATLSCreateKeyAndCrtDer() ([]byte, []byte, error)
```

Creates DER encoded RA-TLS Key and Certificate required for remote attestation in an SGX enclave and return key, certificate and error in the respective order. Currently only [DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives) remote attestation type is supported.

### Verification

The wrapper provides two functions for verifying RATLS certificates:

#### RATLSVerifyDer

```go
func RATLSVerifyDer(cert, mrenclave, mrsigner, isv_prod_id, isv_svn []byte) error
```

`RATLSVerifyDer` verifies a DER-encoded RA-TLS certificate using the given `mrenclave`, `mrsigner`, `isv_prod_id`, and `isv_svn`. If the certificate is valid, this function returns `nil`. If the certificate is invalid, this function returns an error describing the validation failure.

> Note that enclave measurement arguments can be set to *nil*, which causes the verification method to ignore that particular measurement.

#### RATLSVerify

```go
func RATLSVerify(cert, mrenclave, mrsigner, isv_prod_id, isv_svn []byte) error
```

`RATLSVerify` verifies a PEM-encoded RA-TLS certificate using the given SGX measurement args.

## Installation

To use RA-TLS wrapper, you must have Go installed on your system. You can then install it using the following command:

```bash
go get github.com/konvera/gramine-ratls-golang
```

## Initialisation

The wrapper exposes initilisation function: [`InitRATLSLib`](./gramine_ratls_verify.go#L123) which loads the **required** Gramine Remote Attestation libraries and should be called **before** using the RA-TLS functions for certificate creation or verification. It also initialises the in-memory cache and expects following arguments:

- `enabled`: to enable/disable the cache
- `capacity`: cache capacity
- `timeoutInterval`: maximum duration after which value is evicted
- `cacheFailures`: whether to store certificate verification failures

## Usage

To use RA-TLS wrapper, import the `gramine_ratls` package and call the `RATLSCreateKeyAndCrtDer`, `RATLSVerifyDer` or `RATLSVerify` functions depending on the certificate encoding:

```go
func main() {
    // Key and Certificate creation
    key, crt, err := gramine_ratls.RATLSCreateKeyAndCrtDer()

    // Assume that we have a RATLS certificate in a byte slice called "cert"
    // Here we use example values for the measurement args
    mrenclave, _ = hex.DecodeString("f94ccbe6a504676b2edbefdcb8781a512913f7d8864c6f88592a843d0f9d4a66")
    mrsigner, _ = hex.DecodeString("285dd1a739713e723e46f5964310423e21ed08d6d966f890ccb1d4ef9ddec9dd")
    isv_prod_id = []byte{0, 1}
    isv_svn, _ = []byte{0, 1}

    // Certificate verification
    err := gramine_ratls.RATLSVerifyDer(cert, mrenclave, mrsigner, isv_prod_id, isv_svn)
    if err != nil {
     fmt.Printf("Certificate verification failed: %v\n", err)
    } else {
    fmt.Println("Certificate verified successfully.")
}

}
```

In this example, we create DER encoded TLS key and certificate, namely `key`, `crt` using `RATLSCreateKeyAndCrtDer` and also verify another certificate `cert`. Assume that we have a RATLS certificate in a byte slice called `cert`, along with the `mrenclave`, `mrsigner`, `isv_prod_id`, and `isv_svn` values in byte slices. We call the `RATLSVerifyDer` function to verify the certificate.

More info about examples and usage can be found at the [tests](./gramine_ratls_test.go) defined in the repository.

## Logging

The wrapper utilises official `log` package and uses environment variable `DEBUG` to output logs.

## Cache

The package provides a simple in-memory [KV store](./cache/cache.go) that can be used to cache certificate verification result to reduce attestation verification latency. Cache package exports following methods:

- `NewCache(enabled bool, capacity int, timeoutInterval time.Duration, cacheFailures bool)`: used to initialise cache with required arguments
- `Toggle()`: toggle cache support
- `ToggleFailureCaching()`: cache supports caching of failed certificates as well and can be toggled with this method.
- `Add(cert []byte)`: adds new item with timeout duration specified during initialisation.
- `Read(cert []byte)`: reads a value
- `AddItems(certs [][]byte)`: add multiple items to the cache, can be used at the time of initialisation to add multiple successful attestation in advance.