// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

library FrostVerifier {
    uint256 private constant _P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
    uint256 private constant _N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    function _ecmulmuladd(uint256 z, uint256 x, uint256 y, uint256 e) private view returns (address result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, mulmod(z, x, _N))
            mstore(add(ptr, 0x20), add(and(y, 1), 27))
            mstore(add(ptr, 0x40), x)
            mstore(add(ptr, 0x60), mulmod(e, x, _N))
            result := mul(mload(0x00), staticcall(gas(), 0x1, ptr, 0x80, 0x00, 0x20))
        }
    }

    function _address(uint256 x, uint256 y) private pure returns (address result) {
        assembly ("memory-safe") {
            mstore(0x00, x)
            mstore(0x20, y)
            result := and(keccak256(0x00, 0x40), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    function _preimage(uint256 rx, uint256 ry, uint256 px, uint256 py, bytes32 message)
        private
        pure
        returns (bytes memory preimage)
    {
        preimage = new bytes(98);
        assembly ("memory-safe") {
            mstore8(add(preimage, 0x20), add(2, and(ry, 1)))
            mstore(add(preimage, 0x21), rx)
            mstore8(add(preimage, 0x41), add(2, and(py, 1)))
            mstore(add(preimage, 0x42), px)
            mstore(add(preimage, 0x62), message)
        }
    }

    function _expandMessage(bytes memory message, string memory dst, uint256 len)
        private
        view
        returns (bytes memory uniform)
    {
        assembly ("memory-safe") {
            uniform := mload(0x40)
            mstore(0x40, add(uniform, and(add(0x3f, len), 0xffe0)))
            mstore(uniform, len)

            let prime := mload(0x40)
            let ptr := prime

            mstore(ptr, 0)
            ptr := add(ptr, 0x20)
            mstore(ptr, 0)
            ptr := add(ptr, 0x20)

            mcopy(ptr, add(message, 0x20), mload(message))
            ptr := add(ptr, mload(message))
            mstore(ptr, shl(240, len))
            ptr := add(ptr, 3)

            let bPtr := sub(ptr, 0x21)
            let iPtr := sub(ptr, 0x01)

            mcopy(ptr, add(dst, 0x20), mload(dst))
            ptr := add(ptr, mload(dst))
            mstore8(ptr, mload(dst))
            ptr := add(ptr, 0x01)

            let bLen := sub(ptr, bPtr)

            pop(staticcall(gas(), 0x2, prime, sub(ptr, prime), bPtr, 0x20))
            let b0 := mload(bPtr)
            mstore8(iPtr, 1)
            pop(staticcall(gas(), 0x2, bPtr, bLen, add(uniform, 0x20), 0x20))
            for { let i := 2 } gt(len, 0x20) {
                i := add(i, 1)
                len := sub(len, 32)
            } {
                let uPtr := add(uniform, shl(5, i))
                mstore(bPtr, xor(b0, mload(sub(uPtr, 0x20))))
                mstore8(iPtr, i)
                pop(staticcall(gas(), 0x2, bPtr, bLen, uPtr, 0x20))
            }
        }
    }

    function _hashToField(bytes memory message, string memory dst) private view returns (uint256 e) {
        bytes memory uniform = _expandMessage(message, dst, 48);
        assembly ("memory-safe") {
            e := mulmod(mload(add(uniform, 0x20)), 0x100000000000000000000000000000000, _N)
            e := addmod(e, shr(128, mload(add(uniform, 0x40))), _N)
        }
    }

    function _challenge(uint256 rx, uint256 ry, uint256 px, uint256 py, bytes32 message)
        private
        view
        returns (uint256 e)
    {
        return _hashToField(_preimage(rx, ry, px, py, message), "FROST-secp256k1-SHA256-v1chal");
    }

    function verify(bytes32 message, uint256 px, uint256 py, uint256 rx, uint256 ry, uint256 z)
        internal
        view
        returns (address signer)
    {
        uint256 e = _challenge(rx, ry, px, py, message);
        unchecked {
            address minusR = _address(rx, _P - ry);
            address minusRv = _ecmulmuladd(z, px, py, e);

            signer = _address(px, py);
            assembly ("memory-safe") {
                signer := mul(signer, eq(minusR, minusRv))
            }
        }
    }
}
