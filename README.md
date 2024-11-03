# Noir HMAC

Noir HMAC is a implementation of the HMAC algorithm in Noir. It is a simple library that allows you to generate HMAC digests for a given message and secret key.

The Library provides the following methods:

- `hmac_sha256` - Generates a HMAC digest using the SHA-256 hashing algorithm.

## Installation

In your `Nargo.toml` file, add the version of this library you would like to install under dependency:

```toml
[dependencies]
noir_hmac = { tag = "v1.0.2", git = "https://github.com/Envoy-VC/noir_hmac" }
```

## Usage

```noir
fn main() {
    let key: BoundedVec<u8, 256> = BoundedVec::from_array("secret_key".as_bytes());
    let message: BoundedVec<u8, 256> = BoundedVec::from_array("hello".as_bytes());
    let res: [u8; 32] = hmac_sha256(key, message);
}
```
