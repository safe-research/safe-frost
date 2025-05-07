// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.29;

import {Test, Vm, console} from "forge-std/Test.sol";
import {FROSTAccount} from "contracts/FROSTAccount.sol";
import {SafeFROSTSigner} from "contracts/SafeFROSTSigner.sol";
import {SafeFROSTCoSigner} from "contracts/SafeFROSTCoSigner.sol";
import {ISafe, ISafeProxyFactory, SafeDeployments} from "./safe/deployments.sol";
import {IEntryPoint, ERC4337Deployments, PackedUserOperation} from "./erc4337/deployments.sol";

contract E2ETest is Test {
    using SafeFROST for SafeFROST.CLI;

    ISafe singleton;
    ISafeProxyFactory proxyFactory;
    IEntryPoint entryPoint;

    FROSTAccount account;

    function setUp() external {
        (singleton, proxyFactory) = SafeDeployments.setUp(vm);
        entryPoint = ERC4337Deployments.setUp(vm);
        account = new FROSTAccount(address(entryPoint));
    }

    /// @notice End-to-end test executing a Safe transaction authorized by a
    /// FROST signature.
    function test_SafeWithFROSTSigner() external {
        SafeFROST.CLI memory safeFROST = SafeFROST.withRootDirectory(vm, "safe-owner");

        // First things first, generate a secret and, from this secret split it
        // into `--signers` shares with a threshold of `--threshold`.
        //
        // In the real world - this part is kind of complicated as _either_:
        // - You trust a single party to generate a secret and split it into
        //   shares before distributing them to each signer
        // - You use a distributed key generation protocol to trustlessly set up
        //   key shares across the various signers [0]
        //
        // [0]: <https://frost.zfnd.org/tutorial/dkg.html>
        safeFROST.exec("split", "--threshold", "3", "--signers", "5", "--force");

        (, uint256 px, uint256 py) =
            abi.decode(safeFROST.exec("info", "--abi-encode", "public-key"), (address, uint256, uint256));
        SafeFROSTSigner signer = new SafeFROSTSigner(px, py);

        // Set up our Safe owned by a `SafeFROSTSigner` for the public key we
        // just generated.
        ISafe safe;
        {
            address[] memory owners = new address[](1);
            owners[0] = address(signer);
            safe = ISafe(
                proxyFactory.createProxyWithNonce(
                    address(singleton),
                    abi.encodeCall(
                        singleton.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)))
                    ),
                    vm.randomUint()
                )
            );
        }

        // We now want to sign a Safe transaction, so compute its hash and
        // choose `threshold` random participants for signing.
        bytes32 transactionHash =
            safe.getTransactionHash(address(safe), 0, "", 0, 0, 0, 0, address(0), address(0), safe.nonce());
        string[] memory participants = randomSigners(3, 5);

        // # Round 1
        //
        // Now, you perform round 1 of the FROST threshold signature scheme and
        // build the Signing Package.
        //
        // Each Participant (i.e. key share holder) computes random nonces and
        // signing commitments. The commitments are then sent over an
        // authenticated channel (which needs to further be encrypted in case a
        // secret message is being signed) to the Coordinator. The nonces are
        // kept secret to each Participant and will be used later. As a small
        // point of clarification, each Participant generates nonces and
        // commitments _plural_. Both nonces and commitments are generated as a
        // pair of hiding and binding values.
        //
        // Once a threshold of signing commitments are collected, a signing
        // package can be created for collecting signatures from the committed
        // Participants. The Coordinator prepares this signing package and sends
        // it over an authenticated channel to each Participant (again, the
        // channel needs to be encrypted in case the message being signed is
        // secret).
        for (uint256 i = 0; i < participants.length; i++) {
            safeFROST.exec("commit", "--share-index", participants[i]);
        }
        safeFROST.exec("prepare", "--message", vm.toString(transactionHash));

        // # Round 2
        //
        // Once the Signing Package is ready and distributed to the
        // Participants, each can perform their round 2 signature over:
        // - The Signing Package from round 1
        // - The randomly generated nonces from round 1
        // - The secret share
        //
        // The Participant sends their signature share with the Coordinator
        // over, you guessed it, an authenticated (and possibly encrypted)
        // channel.
        //
        // Once the threshold of signature shares have been collected, the
        // Coordinator can generate a Schnorr signature.
        for (uint256 i = 0; i < participants.length; i++) {
            safeFROST.exec("sign", "--share-index", participants[i]);
        }
        safeFROST.exec("aggregate");

        // Finally, we use the aggregate signature for executing the Safe
        // transaction. The signature is the Solidity ABI encoded signature `R`
        // point coordinates and `z` scalar: `abi.encode(rx, ry, z)`.
        bytes memory signature = safeFROST.exec("info", "--abi-encode", "signature");

        bytes4 magicValue = bytes4(keccak256("isValidSignature(bytes32,bytes)"));
        assertEq(signer.isValidSignature(transactionHash, signature), magicValue);

        bytes memory signatures =
            abi.encodePacked(uint256(uint160(address(signer))), uint256(65), uint8(0), signature.length, signature);
        safe.execTransaction(address(safe), 0, "", 0, 0, 0, 0, address(0), payable(address(0)), signatures);
    }

    /// @notice End-to-end test executing a Safe transaction co-signed by a
    /// FROST signature.
    function test_SafeWithFROSTCoSigner() external {
        SafeFROST.CLI memory safeFROST = SafeFROST.withRootDirectory(vm, "safe-co-signer");

        // Generate a secret and deploy a co-signer for it.
        safeFROST.exec("split", "--threshold", "3", "--signers", "5", "--force");

        (, uint256 px, uint256 py) =
            abi.decode(safeFROST.exec("info", "--abi-encode", "public-key"), (address, uint256, uint256));
        SafeFROSTCoSigner coSigner = new SafeFROSTCoSigner(px, py);

        // Create a new Safe account.
        ISafe safe;
        {
            address[] memory owners = new address[](1);
            owners[0] = address(this);
            safe = ISafe(
                proxyFactory.createProxyWithNonce(
                    address(singleton),
                    abi.encodeCall(
                        singleton.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)))
                    ),
                    vm.randomUint()
                )
            );
        }

        // Add the FROST co-signer as a guard.
        bytes memory approvedSignature = abi.encodePacked(uint256(uint160(address(this))), uint256(0), uint8(1));
        bytes memory setGuardData = abi.encodeCall(safe.setGuard, (address(coSigner)));
        safe.execTransaction(
            address(safe), 0, setGuardData, 0, 0, 0, 0, address(0), payable(address(0)), approvedSignature
        );

        // Prepare a transaction and chose random participants for signing.
        bytes32 transactionHash =
            safe.getTransactionHash(address(safe), 0, "", 0, 0, 0, 0, address(0), address(0), safe.nonce());
        string[] memory participants = randomSigners(3, 5);

        // Round 1.
        for (uint256 i = 0; i < participants.length; i++) {
            safeFROST.exec("commit", "--share-index", participants[i]);
        }
        safeFROST.exec("prepare", "--message", vm.toString(transactionHash));

        // Round 2.
        for (uint256 i = 0; i < participants.length; i++) {
            safeFROST.exec("sign", "--share-index", participants[i]);
        }
        safeFROST.exec("aggregate");

        // Read the FROST co-signature.
        bytes memory coSignature = safeFROST.exec("info", "--abi-encode", "signature");

        // Execute the co-signed Safe transaction, the co-signature is appended to the transaction
        // signatures bytes.
        bytes memory signatures = abi.encodePacked(approvedSignature, coSignature);
        safe.execTransaction(address(safe), 0, "", 0, 0, 0, 0, address(0), payable(address(0)), signatures);
    }

    /// @notice End-to-end test executing an account-abstracted ERC-7702
    /// multi-signature FROST transaction.
    function test_FROSTAccount() external {
        SafeFROST.CLI memory safeFROST = SafeFROST.withRootDirectory(vm, "account");

        // Pick a private key, and delegate to the FROST account.
        Vm.Wallet memory wallet = vm.createWallet("user");
        vm.signAndAttachDelegation(address(account), wallet.privateKey);

        // Split the private key into shares for signing user operations.
        safeFROST.exec(
            "split",
            "--threshold",
            "3",
            "--signers",
            "5",
            "--force",
            "--secret-key",
            vm.toString(bytes32(wallet.privateKey))
        );

        (, uint256 px, uint256 py) =
            abi.decode(safeFROST.exec("info", "--abi-encode", "public-key"), (address, uint256, uint256));

        // Prepare a user operation and chose random participants for signing.
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: wallet.addr,
            nonce: entryPoint.getNonce(wallet.addr, 0),
            initCode: hex"7702",
            callData: abi.encodeCall(account.execute, (wallet.addr, 0, "")),
            accountGasLimits: bytes32(uint256((1000000 << 128) + 1000000)),
            preVerificationGas: 1000000,
            gasFees: bytes32(uint256((1 gwei << 128) + 1 gwei)),
            paymasterAndData: "",
            signature: ""
        });
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        string[] memory participants = randomSigners(3, 5);

        // Round 1.
        for (uint256 i = 0; i < participants.length; i++) {
            safeFROST.exec("commit", "--share-index", participants[i]);
        }
        safeFROST.exec("prepare", "--message", vm.toString(userOpHash));

        // Round 2.
        for (uint256 i = 0; i < participants.length; i++) {
            safeFROST.exec("sign", "--share-index", participants[i]);
        }
        safeFROST.exec("aggregate");

        // Read the FROST co-signature. Note that we additionally pack the group
        // public key into the signature as it is needed for verification and
        // not available to the delegated contract (since there is no setup
        // function).
        bytes memory signature = abi.encodePacked(px, py, safeFROST.exec("info", "--abi-encode", "signature"));

        // Fund the account and execute the user operation.
        vm.deal(wallet.addr, 1 ether);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;
        ops[0].signature = signature;
        entryPoint.handleOps(ops, payable(wallet.addr));
    }

    function randomSigners(uint256 threshold, uint256 count) internal returns (string[] memory signers) {
        assertLt(threshold, count);

        signers = new string[](count);
        for (uint256 i = 0; i < count; i++) {
            signers[i] = vm.toString(i);
        }

        for (uint256 n = count - 1; n > 0; n--) {
            uint256 i = vm.randomUint(0, n);

            string memory temp = signers[i];
            signers[i] = signers[n];
            signers[n] = temp;
        }

        assembly ("memory-safe") {
            mstore(signers, threshold)
        }

        return signers;
    }
}

library SafeFROST {
    struct CLI {
        Vm vm;
        string root;
    }

    function withRootDirectory(Vm vm, string memory tag) internal pure returns (CLI memory) {
        string memory root = string(abi.encodePacked(".frost/", tag));
        return CLI(vm, root);
    }

    function exec(CLI memory self, string memory subcommand, string[] memory options) internal returns (bytes memory) {
        string[] memory ffi = new string[](7 + options.length);
        ffi[0] = "cargo";
        ffi[1] = "run";
        ffi[2] = "-q";
        ffi[3] = "--";
        ffi[4] = "--root-directory";
        ffi[5] = self.root;
        ffi[6] = subcommand;
        for (uint256 i = 0; i < options.length; i++) {
            ffi[7 + i] = options[i];
        }
        return self.vm.ffi(ffi);
    }

    function exec(CLI memory self, string memory subcommand) internal returns (bytes memory) {
        return exec(self, subcommand, new string[](0));
    }

    function exec(CLI memory self, string memory subcommand, string memory option1) internal returns (bytes memory) {
        string[] memory options = new string[](1);
        options[0] = option1;
        return exec(self, subcommand, options);
    }

    function exec(CLI memory self, string memory subcommand, string memory option1, string memory option2)
        internal
        returns (bytes memory)
    {
        string[] memory options = new string[](2);
        options[0] = option1;
        options[1] = option2;
        return exec(self, subcommand, options);
    }

    function exec(
        CLI memory self,
        string memory subcommand,
        string memory option1,
        string memory option2,
        string memory option3
    ) internal returns (bytes memory) {
        string[] memory options = new string[](3);
        options[0] = option1;
        options[1] = option2;
        options[2] = option3;
        return exec(self, subcommand, options);
    }

    function exec(
        CLI memory self,
        string memory subcommand,
        string memory option1,
        string memory option2,
        string memory option3,
        string memory option4
    ) internal returns (bytes memory) {
        string[] memory options = new string[](4);
        options[0] = option1;
        options[1] = option2;
        options[2] = option3;
        options[3] = option4;
        return exec(self, subcommand, options);
    }

    function exec(
        CLI memory self,
        string memory subcommand,
        string memory option1,
        string memory option2,
        string memory option3,
        string memory option4,
        string memory option5
    ) internal returns (bytes memory) {
        string[] memory options = new string[](5);
        options[0] = option1;
        options[1] = option2;
        options[2] = option3;
        options[3] = option4;
        options[4] = option5;
        return exec(self, subcommand, options);
    }

    function exec(
        CLI memory self,
        string memory subcommand,
        string memory option1,
        string memory option2,
        string memory option3,
        string memory option4,
        string memory option5,
        string memory option6,
        string memory option7
    ) internal returns (bytes memory) {
        string[] memory options = new string[](7);
        options[0] = option1;
        options[1] = option2;
        options[2] = option3;
        options[3] = option4;
        options[4] = option5;
        options[5] = option6;
        options[6] = option7;
        return exec(self, subcommand, options);
    }
}
