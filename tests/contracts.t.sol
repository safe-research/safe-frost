// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {SafeFROSTSigner} from "../contracts/SafeFROSTSigner.sol";

contract ContractsTest is Test {
    function setUp() external {}

    function test_Signer() external {
        uint256 px = 0x4cab98e35c9c2803dee2aca757604414d7c73e5a2d0a7cc1fb0f2371856e7426;
        uint256 py = 0x52bd6b2fb4c1e5bb10b06cfd01cd4fd70cad7604b880a4d4da9a3455cf240637;

        SafeFROSTSigner signer = new SafeFROSTSigner(px, py);

        bytes memory messagePreimage = "Hello, FROST!";
        bytes32 message = keccak256(messagePreimage);

        uint256 rx = 0xb9c35c1444e790346f9dde685ce3dd101a39623df1cbbd5a3b07c594f945ccac;
        uint256 ry = 0xd982091c53df54a7e846316d07a6f79e3971795c694c2dedf9718c4c81a51de7;
        uint256 z = 0x109c90aa8729baa999dbec6318e7ab32a44121ddf029141708e77b82ede02bfd;
        bytes memory signature = abi.encode(rx, ry, z);

        bytes4 magicValue = bytes4(keccak256("isValidSignature(bytes32,bytes)"));
        assertEq(signer.isValidSignature(message, signature), magicValue);

        bytes4 legacyMagicValue = bytes4(keccak256("isValidSignature(bytes,bytes)"));
        assertEq(signer.isValidSignature(messagePreimage, signature), legacyMagicValue);
    }
}
