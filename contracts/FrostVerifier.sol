// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

contract FrostVerifier {
    uint256 constant private _N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 constant private _P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;

    function _ecmulmuladd(uint256 z, uint256 x, uint256 y, uint256 e) private view returns (address result) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, mulmod(z, x, _N))
            mstore(add(ptr, 0x20), add(and(y, 1), 27))
            mstore(add(ptr, 0x40), x)
            mstore(add(ptr, 0x60), mulmod(e, x, _N))
            result := mul(
                mload(0x00),
                staticcall(gas(), 0x1, ptr, 0x80, 0x00, 0x20)
            )
        }
    }

    function _address(uint256 x, uint256 y) private pure returns (address result) {
        assembly ("memory-safe") {
            mstore(0x00, x)
            mstore(0x20, y)
            result := and(keccak256(0x00, 0x40), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    function _preimage(uint256 rx, uint256 ry, uint256 px, uint256 py, bytes32 message) private pure returns (bytes memory preimage) {
        preimage = new bytes(98);
        assembly ("memory-safe") {
            mstore8(add(preimage, 0x20), add(2, and(ry, 1)))
            mstore(add(preimage, 0x21), rx)
            mstore8(add(preimage, 0x41), add(2, and(py, 1)))
            mstore(add(preimage, 0x42), px)
            mstore(add(preimage, 0x62), message)
        }
    }

    function _expandMessage(bytes memory message, string memory dst, uint256 len) private view returns (bytes memory uniform) {
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
            for {
                let i := 2
            } gt(len, 0x20) {
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

    function _challenge(uint256 rx, uint256 ry, uint256 px, uint256 py, bytes32 message) private view returns (uint256 e) {
        return _hashToField(
            _preimage(rx, ry, px, py, message),
            "FROST-secp256k1-SHA256-v1chal"
        );
    }

    function _verify(
        bytes32 message,
        uint256 px, uint256 py,
        uint256 rx, uint256 ry,
        uint256 z
    ) internal view returns (address signer) {
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

    function test() public view returns (address) {
        return _verify(
            0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532,
            0x51177dde89242d9121d787a681bd2a0bd6013428a6b83e684a253815db96d8b3,
            0xbd42c409d2f0f0c805fb913f2066f597e0df65451bca3e81ca718afaa0763de3,
            0xb4e9386c48280fa5b7e15c1130e7903492477255ebed3dbc43b2d17d0be5667c,
            0x204afdf5d544311185e1abd81a1b6a52fdc3674d5de59f82c957b634d6779c4c,
            0x5040882C2C74C66E02C8096493EA5991D06CCC2222F69243A061246412834829
        );
    }
}

// 0x616263, "QUUX-V01-CS02-with-expander-SHA256-128", 32
// 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000616263002000515555582d5630312d435330322d776974682d657870616e6465722d5348413235362d31323826
// 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000616263002000515555582d5630312d435330322d776974682d657870616e6465722d5348413235362d31323826

// 0x77ad56c16b22030bb618241e422f48b883a5d3941a07fa67a7bde8b01b982024
// 0x77ad56c16b22030bb618241e422f48b883a5d3941a07fa67a7bde8b01b98202401515555582d5630312d435330322d776974682d657870616e6465722d5348413235362d31323826
// 0x77ad56c16b22030bb618241e422f48b883a5d3941a07fa67a7bde8b01b98202401515555582d5630312d435330322d776974682d657870616e6465722d5348413235362d31323826

// 0x616263, "QUUX-V01-CS02-with-expander-SHA256-128", 128
// 0xabba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40
// 0xabba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40
// 0xabba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40

// 0xb4e9386c48280fa5b7e15c1130e7903492477255ebed3dbc43b2d17d0be5667c, 0x204afdf5d544311185e1abd81a1b6a52fdc3674d5de59f82c957b634d6779c4c, 0x51177dde89242d9121d787a681bd2a0bd6013428a6b83e684a253815db96d8b3, 0xbd42c409d2f0f0c805fb913f2066f597e0df65451bca3e81ca718afaa0763de3, 0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
// 0x02b4e9386c48280fa5b7e15c1130e7903492477255ebed3dbc43b2d17d0be5667c0351177dde89242d9121d787a681bd2a0bd6013428a6b83e684a253815db96d8b33a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
// 0x02b4e9386c48280fa5b7e15c1130e7903492477255ebed3dbc43b2d17d0be5667c0351177dde89242d9121d787a681bd2a0bd6013428a6b83e684a253815db96d8b33a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
// 0x43ee5a34630adb3a88502e46d208aa08fdb0685dc06f06d41f83b9f1309a4fef9ab683875cab2d1b7edc4d563fc53a74
// 0x5403889d1ac64339558373d64c5eec355fb125f412b4de39fb9aef1f8a7fc52b
// 0x5403889d1ac64339558373d64c5eec355fb125f412b4de39fb9aef1f8a7fc52b

// 0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532, 0x51177dde89242d9121d787a681bd2a0bd6013428a6b83e684a253815db96d8b3, 0xbd42c409d2f0f0c805fb913f2066f597e0df65451bca3e81ca718afaa0763de3, 0xb4e9386c48280fa5b7e15c1130e7903492477255ebed3dbc43b2d17d0be5667c, 0x204afdf5d544311185e1abd81a1b6a52fdc3674d5de59f82c957b634d6779c4c, 0x5040882C2C74C66E02C8096493EA5991D06CCC2222F69243A061246412834829
