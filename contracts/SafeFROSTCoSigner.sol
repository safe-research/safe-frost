// SPDX-License-Identifier: GPL-3.0-only
pragma solidity =0.8.29;

import {FROST} from "./FROST.sol";
import {IERC165, ISafeTransactionGuard} from "./interfaces/ISafeTransactionGuard.sol";

contract SafeFROSTCoSigner is ISafeTransactionGuard {
    /// @notice The x-coordinate of the signer's public key.
    uint256 private immutable _PX;
    /// @notice The y-coordinate of the signer's public key.
    uint256 private immutable _PY;
    /// @notice The public address of the signer.
    address private immutable _SIGNER;

    /// @notice The transaction was not co-signed.
    error Unauthorized();
    /// @notice Execution imbalance.
    /// @dev This happens for misbehaving callers where `checkTransaction` is
    /// called fewer times than `checkAfterExecution`.
    error ExecutionImbalance();

    constructor(uint256 px, uint256 py) {
        _PX = px;
        _PY = py;
        _SIGNER = address(uint160(uint256(keccak256(abi.encode(px, py)))));
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) external view virtual override returns (bool) {
        return interfaceId == type(ISafeTransactionGuard).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    /// @inheritdoc ISafeTransactionGuard
    function checkTransaction(
        address,
        uint256,
        bytes calldata,
        uint8,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes calldata signatures,
        address
    ) external {
        bytes calldata signature = signatures[signatures.length - 96:];
        uint256 rx;
        uint256 ry;
        uint256 z;
        assembly ("memory-safe") {
            rx := calldataload(signature.offset)
            ry := calldataload(add(signature.offset, 0x20))
            z := calldataload(add(signature.offset, 0x40))
        }
        _pushSignature(rx, ry, z);
    }

    /// @inheritdoc ISafeTransactionGuard
    function checkAfterExecution(bytes32 safeTxHash, bool) external {
        (uint256 rx, uint256 ry, uint256 z) = _popSignature();
        require(FROST.verify(safeTxHash, _PX, _PY, rx, ry, z) == _SIGNER, Unauthorized());
    }

    function _pushSignature(uint256 rx, uint256 ry, uint256 z) private {
        assembly ("memory-safe") {
            mstore(0x00, caller())
            mstore(0x20, 0)
            let slot := keccak256(0x00, 0x40)
            let count := tload(slot)
            let offset := add(slot, mul(count, 3))
            tstore(slot, add(count, 1))
            tstore(add(offset, 1), rx)
            tstore(add(offset, 2), ry)
            tstore(add(offset, 3), z)
        }
    }

    function _popSignature() private returns (uint256 rx, uint256 ry, uint256 z) {
        uint256 count;
        assembly ("memory-safe") {
            mstore(0x00, caller())
            mstore(0x20, 0)
            let slot := keccak256(0x00, 0x40)
            count := tload(slot)
            let offset := add(slot, mul(count, 3))
            tstore(slot, sub(count, 1))
            rx := tload(sub(offset, 2))
            ry := tload(sub(offset, 1))
            z := tload(offset)
        }
        require(count > 0, ExecutionImbalance());
    }
}
