// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {FROST} from "contracts/FROST.sol";

contract FROSTTest is Test {
    function setUp() public {}

    function test_Verify() public view {
        bytes32 message = 0x4141414141414141414141414141414141414141414141414141414141414141;

        uint256 px = 0x4F6340CFDD930A6F54E730188E3071D150877FA664945FB6F120C18B56CE1C09;
        uint256 py = 0x802A5E67C00A70D85B9A088EAC7CF5B9FB46AC5C0B2BD7D1E189FAC210F6B7EF;

        uint256 rx = 0x501DCFE29D881AA855BF25979BD79F751AA9536AF7A389403CD345B02D1E6F25;
        uint256 ry = 0x839AD3B762F50FE560F4688A15A1CAED522919F33928567F95BC48CBD9B8C771;

        uint256 z = 0x4FDEA9858F3E6484F1F0D64E7C17879C25F68DA8BD0E82B063CF7410DDF5A886;

        address addr;
        assembly ("memory-safe") {
            mstore(0x00, px)
            mstore(0x20, py)
            addr := and(keccak256(0x00, 0x40), sub(shl(160, 1), 1))
        }

        assertEq(FROST.verify(message, px, py, rx, ry, z), addr);
    }

    function test_VerifyWithInvalidPublicKey() public view {
        // bug originally found here:
        // https://github.com/chronicleprotocol/scribe/issues/56
        // merkleplant raised this topic in X and on forum:
        // https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384/19

        bytes32 message = 0x4141414141414141414141414141414141414141414141414141414141414141;

        // this bug with ecrecover happens when public key X
        // in range `[0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)`
        // this can happen with `1 / 2^128` chance

        uint256 px = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141; // public key x >= Secp256k1.N
        uint256 py = 0x98F66641CB0AE1776B463EBDEE3D77FE2658F021DB48E2C8AC7AB4C92F83621E;

        uint256 rx = 0x0000000000000000000000000000000000000000000000000000000000000001;
        uint256 ry = 0x4218F20AE6C646B363DB68605822FB14264CA8D2587FDD6FBC750D587E76A7EE;

        uint256 z = 0x4242424242424242424242424242424242424242424242424242424242424242;

        assertEq(FROST.verify(message, px, py, rx, ry, z), address(0));
        assertFalse(FROST.isValidPublicKey(px, py));
    }
}
