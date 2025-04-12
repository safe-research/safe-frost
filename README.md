:warning: **Code in this repository is not audited and may contain serious security holes; use at your own risk.** :warning:

# FROST Signatures

This repository implements FROST(secp256k1, SHA-256) signature aggregation, and on-chain signature verification. Unlike other implementations, this one matches the FROST standard exactly without modifications to make it more efficient on the EVM.

As of writing, signature verification is only **~5500 gas** (with the optimizer enabled, only execution of the `Frost.verify` function itself excluding things like calldata cost), which is crazy good!

## Usage

### Signing

Generate a random private key split into shares, and use them to sign a message:

```sh
cargo run -- 0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
```

To see all supported options and flags:

```sh
cargo run -- --help
```

### Verifying

The above command will output all required information in order to verify a signature on-chain by calling `Frost.verify(...)`. For example:

```
cargo run -q -- 0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
---------------------------------------------------------------------
address:    0x908003F669F854E212b33E6f6bdCD92Fa324820d
public key: {0xdca18f3684bc5215cab42a1408349aa8c6c8c8618828c10f42c3267a2f244af2,0x59df12ce44f6103f21776987ae8abd0e41867bafb1031eab70b76ff5c312c337}
signature:  {0x5670147d167303169aca1076e7c6f41ec9bf5f218f4062e9510a03f157876617,0x4a76a3b5c324d141037e198dccee4cad8218cb136657a9e677007003ab1520a6}
            0xddf02a70a147d67d5051e94e60a123032cd1b779c1697522c0aa7453246beb65
---------------------------------------------------------------------
Frost.verify(0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532, 0xdca18f3684bc5215cab42a1408349aa8c6c8c8618828c10f42c3267a2f244af2, 0x59df12ce44f6103f21776987ae8abd0e41867bafb1031eab70b76ff5c312c337, 0x5670147d167303169aca1076e7c6f41ec9bf5f218f4062e9510a03f157876617, 0x4a76a3b5c324d141037e198dccee4cad8218cb136657a9e677007003ab1520a6, 0xddf02a70a147d67d5051e94e60a123032cd1b779c1697522c0aa7453246beb65) == 0x908003F669F854E212b33E6f6bdCD92Fa324820d
---------------------------------------------------------------------
```

This signature can be verified on-chain with (with some formatting):

```solidity
Frost.verify(
    0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532,
    0xdca18f3684bc5215cab42a1408349aa8c6c8c8618828c10f42c3267a2f244af2,
    0x59df12ce44f6103f21776987ae8abd0e41867bafb1031eab70b76ff5c312c337,
    0x5670147d167303169aca1076e7c6f41ec9bf5f218f4062e9510a03f157876617,
    0x4a76a3b5c324d141037e198dccee4cad8218cb136657a9e677007003ab1520a6,
    0xddf02a70a147d67d5051e94e60a123032cd1b779c1697522c0aa7453246beb65
) == 0x908003F669F854E212b33E6f6bdCD92Fa324820d
```

## Documentation

I made an effort to add a lot of detailed documentation inline with the code, so please read through `main.rs` and `Frost.sol` for more information.

## Prior Art

This isn't the first attempt at bringing threshold secp256k1 signatures to the EVM. In fact, Chainlink had a [blog post](https://blog.chain.link/threshold-signatures-in-chainlink/) about this many years ago, and their own implementation of threshold Schnorr signatures. Additionally, others [have modified FROST](https://github.com/Analog-Labs/frost-evm) with a custom ciphersuite specifically designed for efficient EVM verification. In particular, it modifies the challenge computation such that:
1. The challenge pre-image is computed with the **address** of the R signature point; reducing calldata size (you no longer need to send the full coordinates of the `R` signature point), and making it so don't need to compute the address of `R` on-chain to compare it with the result from the `ecrecover` precompile.
2. It uses a simple Keccak-256 hash instead of hashing to a field element as defined in [RFC-9380](https://datatracker.ietf.org/doc/html/rfc9380); which simplifies the code required to compute the challenge on-chain.

While these modifications simplify the Solidity implementation of signature verification, they deviate from the FROST standard specified in [RFC-9591](https://datatracker.ietf.org/doc/html/rfc9591) and it [does not](https://github.com/ZcashFoundation/frost/issues/319#issuecomment-1524046665) [seem likely](https://github.com/ZcashFoundation/frost/pull/749#issuecomment-2506270083) that a modified EVM-specific ciphersuite will be accepted into FROST. Furthermore, we found that a full implementation of signature verification for the FROST(secp256k1, SHA-256) ciphersuite is quite efficient in the EVM, so deviating from the standard is not necessary.
