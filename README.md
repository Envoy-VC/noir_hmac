# Noir HMAC

Noir HMAC is a implementation of the HMAC algorithm in Noir. It is a simple library that allows you to generate HMAC digests for a given message and secret key.

The Library provides the following methods:

- `hmac_sha256` - Generates a HMAC digest using the SHA-256 hashing algorithm.
- `hmac_sha256_var` Generates a HMAC digest on Vector Inputs using the SHA-256 hashing algorithm.

## Installation

In your `Nargo.toml` file, add the version of this library you would like to install under dependency:

```toml
[dependencies]
noir_hmac = { tag = "v1.0.0", git = "https://github.com/Envoy-VC/noir_hmac" }
```

## Usage

For Fixed Size Arrays:

```noir
use noir_hmac::hmac_sha256;

fn main() {
    let key: [u8; 48] = "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA458448366".as_bytes();
    let message: [u8; 5] = "hello".as_bytes();
    let res: [u8; 32] = hmac_sha256(key, message);
}
```

For Dynamic Sized Vectors:

```noir
use noir_hmac::hmac_sha256_var;

fn main() {
    let key: Vec<u8> = "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA458448366".as_bytes_vec();
    let message: Vec<u8> = "hello".as_bytes_vec();
    let res: [u8; 32] = hmac_sha256_var(key, message, message.len());
}
```
