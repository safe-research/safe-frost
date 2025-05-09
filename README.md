:warning: **Code in this repository is not audited and may contain serious security holes; use at your own risk.** :warning:

# Safe + FROST

This repository implements a FROST(secp256k1, SHA-256) verifier for the EVM, as well as contracts to integrate FROST signatures with the Safe smart account, bringing an efficient threshold signature scheme to Safes. Unlike other implementations, this one matches the FROST standard exactly without modifications (such as adjusting the hash function) to make it more efficient on the EVM.

As of writing, signature verification, regardless of the number of the threshold or number of shares, is only **~5600 gas** (with the optimizer enabled, only execution of the `FROST.verify` function itself excluding things like signature decoding and calldata cost), which is crazy good!

`safe-frost` supports three main use cases of FROST signatures:

- as a Safe signer
- as a Safe co-signer
- as a delegation target for EIP-7702, with ERC-4337 support

## Installation

This repository provides a basic `safe-frost` CLI tool for working with FROST signatures, and the _Usage_ section below assumes that the tool is installed:

```sh
cargo install
```

If you do not want to install the tool, you can instead just run it with `cargo`:

```sh
alias safe-frost="cargo run --release -q --"
```

By default, the tool outputs files to a `.frost/` directory (relative to the working directory from where the tool is executed). This includes the root public key, shares, and other intermediate files from the signing process.

Since the on-chain signature verifier follows the FROST standard, you can use any other tool for creating FROST(secp256k1, SHA-256) signatures.

## Usage

At its core, FROST is a threshold signature scheme. This means it allows splitting a root secret key into `n` shares for a threshold `t`, such that at least `t` participants need to cooperate to generate a signature that can be verified by the root public key. Here, we specifically implement FROST(secp256k1, SHA-256), meaning that the root secret key and public key are just a secp256k1 key pair (i.e. "regular Ethereum EOA").

FROST only generates Schnorr signatures, and not ECDSA signatures (the standard used by Ethereum), which is why additional EVM contracts are actually needed for verifying these signatures on-chain (instead of just using the `ecrecover` precompile or signing native Ethereum transactions). It is also important to note that FROST signatures are indistinguishable from normal signatures, so no one (including the verifier) can tell the difference between the root signing key and a threshold of shares producing a signature.

### Roles

The FROST signature scheme has three primary roles that interact with each other in order to generate a signature:

- _Dealer_: This is the party responsible for splitting the root secret keys into shares and distributing them to each of the signers. They are only involved in the initial key generation process and do not participate in any subsequent signing process. The dealer is not necessary if the shares are generated using a [distributed key generation](https://frost.zfnd.org/tutorial/dkg.html) process. This party has access to:
  - The root secret key
  - The root public key `.frost/key.pub`
  - The key shares for **each** signer `.frost/key.${index}`
- _Signer_: This is the party that has a key share and uses it to generate a signature share for a message. A threshold of signers is required in order to generate a valid signature for the root public key. We call signers that are involved in a signing ritual a _Participant_. This party has access to:
  - Their individual key share `.frost/key.${index}`
  - Their individual random nonces used for signing `.frost/round1.${index}.nonces`
  - Their individual commitments to the random nonces `.frost/round1.${index}.commitments`
  - The signing package `.frost/round1`
  - Their individual signature shares `.frost/round2.${index}.shares`
- _Coordinator_: This is the party responsible for collecting commitments for building a signing package, as well as collecting signature shares for aggregating into a final signature. This party has access to:
  - The root public key `.frost/key.pub`
  - The commitments to the nonces for **each** participant `.frost/round1.${index}.commitments`
  - The signing package `.frost/round1`
  - The signature shares for **each** participant `.frost/round2.${index}.shares`
  - The aggregate signature `.frost/round2`

### Generating a Key and Shares

The first step is to generate shares from a root secret key. We assume that you have a trusted dealer to generate the shares and distribute them to each of the signers:

```sh
# Generate a new random secp256k1 root key pair:
safe-frost split --threshold 3 --signers 5
# Or split an existing secp256k1 secret key:
safe-frost split --secret-key 0x... --threshold 3 --signers 5
```

This will generate a `.frost/key.pub` file containing the root public key, and `n` `.frost/key.${index}` files containing each of the shares intended to be distributed to each of the signers. You can view information about the root public key with:

```sh
safe-frost info public-key
```

Which will output something like:

```
address:    0x040c77563f37a6e1d8c2786f577AEd60B2FefCb1
public key: {0x7aac43e357aebb9546841b13a80093789d6b308bcfd64e91164d281c8d33ba0c,0xbd429a344ce5c8082b6de1b08c8140edcfaf40905ee383bbdfc3866275107495}
```

With the root public key in place, we can now configure a Safe with a FROST signer:

- In order to use the root key as an owner of a Safe, you need to deploy a `SafeFROSTSigner` configured with the root public key, and add it as a Safe owner:
  ```solidity
  SafeFROSTSigner signer = new SafeFROSTSigner(px, py);
  safe.execTransaction(
      address(safe), 0, abi.encodeCall(safe.addOwner, (address(signer))), 0, // ...
  )
  ```
- In order to use the root key as a co-signer for a Safe, you need to deploy a `SafeFROSTCoSigner` configured with the root public key, and add set it as a Safe guard.
  ```solidity
  SafeFROSTCoSigner coSigner = new SafeFROSTCoSigner(px, py);
  safe.execTransaction(
      address(safe), 0, abi.encodeCall(safe.setGuard, (address(coSigner))), 0, // ...
  )
  ```

### Signing Safe Transactions

FROST signatures are generated in two rounds:

- In the first round, the participants commit to nonces that they will use. The coordinator then builds a signing package from the message to sign and the commitments from each of the participants.
- In the second round, the participants sign the package with their key share and the nonces generated in the first round. The coordinator then aggregates the participants' signatures into single Schnorr signature.

The resulting signature from the second round, which consists of a secp256k1 point `R` and scalar `z` can be verified on-chain and used to authorize transactions on a Safe.

#### Setup

To start, we need to compute the message to sign:

```solidity
bytes32 safeTxHash = safe.getTransactionHash(
    to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce
);
```

#### Round 1

The first round consists of generating random (secret) nonces and their commitments for each participant:

```sh
for participant in $participants; do
  safe-frost sign --share-index $participant
done
```

This will generate `.frost/round1.${participant}.nonces` and `.frost/round1.${participant}.commitments` files for each participants (containing the secret nonces and their commitments for each participant). Once these files have been generated, the commitments need to be sent to the coordinator and used to generate a signing package. This includes the message to sign and will be sent to each participant in round 2 for them to generate a signature share:

```sh
safe-frost prepare --message $safeTxHash
```

This will generate a `.frost/round1` signing package.

#### Round 2

Now that the signing package is ready, round 2 can begin. In this round of the threshold signature scheme, each participant will use their key share `.frost/key.${participant}` and `.frost/round1.${participant}.nonces` to generate a signature share `.frost/round2.${participant}` for the signing package `.frost/round1`:

```sh
for participant in $participants; do
  safe-frost sign --share-index $participant
done
```

Finally, the `.frost/key.pub` root public key, the `.frost/round1` signing package and all participant's `.frost/round2.${participant}` signature shares need to be aggregated into a FROST signature file `.frost/round2`:

```sh
safe-frost aggregate
```

This signature can now be used to verify the `safeTxHash` message with the root public key and used for executing a Safe transaction!

```sh
safe-frost info --abi-encode signature
```

### EIP-7702 Delegation

Once the account has signed and attached a delegation to the `FROSTAccount` contract by EIP-7702, FROST signatures can authorize ERC-4337 user operations on behalf of the account. Note that, since FROST(secp256k1, SHA-256) uses the same curve as Ethereum, the public key and address of the group are the same as the externally owned account (EOA). This essentially allows you to upgrade your existing EOA into a multi-signature account.

#### Key Generation

It is possible to split an existing private key into shares for use with the `FROSTAccount`:

```sh
safe-frost split --threshold 3 --signers 5 --secret-key $YOUR_PRIVATE_KEY
```

This will create a FROST group with the same public address as the EOA corresponding to the supplied private key.

#### Setup

Since the `FROSTAccount` is an ERC-4337 account, instead of signing Safe transactions, you would sign user operations:

```solidity
bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
```

User operations are executed over the ERC-4337 entry point contract and can take full advantage of the bundler network.

#### Signature Format

Other than a different signing message, the process for generating a signature is the same as generating one for a Safe transaction. In other words, both signing rounds need to be performed in the same way, but the `userOpHash` is used as the signing message instead of a `safeTxHash`. Additionally, because of how the account is implemented and since public keys are not computable for a given Ethereum public address, the user operation signature expects a slightly different format to the Safe owner. In particular, it expects the encoded public key X and Y coordinates, packed with the usual FROST signature that is used by the Safe owner and co-signer:

```solidity
userOp.signature = abi.encodePacked(px, py, signature);
```

### Examples

The whole flow for signing a Safe transaction, both as an owner and as a co-signer, as well as signing a user operation, is documented as end-to-end tests in [`tests/e2e.t.sol`](tests/e2e.t.sol). They include detailed comments explaining what each step of the signing process is doing. The end-to-end tests can be executed with `forge`:

```sh
forge test --ffi
```

Note that the tests require `forge` FFI, in order to execute `safe-frost` CLI commands.

## Prior Art

This isn't the first attempt at bringing threshold secp256k1 signatures to the EVM. In fact, Chainlink had a [blog post](https://blog.chain.link/threshold-signatures-in-chainlink/) about this many years ago, and their own implementation of threshold Schnorr signatures. Additionally, others [have modified FROST](https://github.com/Analog-Labs/frost-evm) with a custom ciphersuite specifically designed for efficient EVM verification. In particular, it modifies the challenge computation such that:

1. The challenge pre-image is computed with the **address** of the R signature point; reducing calldata size (you no longer need to send the full coordinates of the `R` signature point), and making it so don't need to compute the address of `R` on-chain to compare it with the result from the `ecrecover` precompile.
2. It uses a simple Keccak-256 hash instead of hashing to a field element as defined in [RFC-9380](https://datatracker.ietf.org/doc/html/rfc9380); which simplifies the code required to compute the challenge on-chain.

While these modifications simplify the Solidity implementation of signature verification, they deviate from the FROST standard specified in [RFC-9591](https://datatracker.ietf.org/doc/html/rfc9591) and it [does not](https://github.com/ZcashFoundation/frost/issues/319#issuecomment-1524046665) [seem likely](https://github.com/ZcashFoundation/frost/pull/749#issuecomment-2506270083) that a modified EVM-specific ciphersuite will be accepted into FROST. Furthermore, we found that a full implementation of signature verification for the FROST(secp256k1, SHA-256) ciphersuite is quite efficient in the EVM, so deviating from the standard is not necessary at all.
