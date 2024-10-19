# Noir HMAC

Noir HMAC is a implementation of the HMAC algorithm in Noir. It is a simple library that allows you to generate HMAC digests for a given message and secret key.

The Library provides the following methods:

- `hmac_sha256` - Generates a HMAC digest using the SHA-256 hashing algorithm.

## Installation

In your Nargo.toml file, add the version of this library you would like to install under dependency:

```toml
[dependencies]
noir_hmac = { tag = "v1.0.0", git = "https://github.com/Envoy-VC/noir_hmac" }
```

## Usage

```noir
use noir_hmac::hmac_sha256;

fn main() {
    let key: [u8; 48] = "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA458448366".as_bytes();
    let message: [u8; 5] = "hello".as_bytes();
    let res: [u8; 32] = hmac_sha256(key, message);
}
```
