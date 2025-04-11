// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

contract FrostVerifier {
    uint256 constant private _N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function _ecmul(uint256 x, uint256 y, uint256 scalar) internal view returns (address result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 0)
            mstore(add(ptr, 0x20), add(and(y, 1), 27))
            mstore(add(ptr, 0x40), x)
            mstore(add(ptr, 0x60), mulmod(scalar, x, _N))
            result := mul(
                mload(0x00),
                staticcall(gas(), 0x1, ptr, 0x80, 0x00, 0x20)
            )
        }
        return ecrecover(0, y % 2 != 0 ? 28 : 27, bytes32(x), bytes32(mulmod(scalar, x, _N)));
    }

    function _address(uint256 x, uint256 y) internal pure returns (address result) {
        assembly ("memory-safe") {
            mstore(0x00, x)
            mstore(0x20, y)
            result := and(keccak256(0x00, 0x40), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }
}