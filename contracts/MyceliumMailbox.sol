// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.20;

/// @title MyceliumMailbox
/// @notice Scalable inbox for mycelium on EVM chains. Instead of scanning every
///         block for txs addressed to a recipient (slow on busy chains), a
///         recipient registers here and mycelium messages are stored as opaque
///         E2E-encrypted blobs, addressed by recipient, with a log event the
///         recipient's indexer polls via eth_getLogs.
///
/// @dev The mailbox NEVER holds a key. The blob is mycelium's E2E envelope
///      (eph_pub || nonce || ciphertext) produced by internal/secure — the
///      contract only stores and re-emits opaque bytes. Privacy comes from m³
///      crypto, not from this contract.
contract MyceliumMailbox {
    /// Emitted when a message is delivered to a recipient. Recipients poll
    /// Inbox(to=us) via eth_getLogs — cheap, no full block scan.
    event Inbox(address indexed to, address indexed from, uint256 indexed seq, bytes32 cid);

    struct Message {
        address from;
        uint256 blockNumber;
        bytes data; // opaque mycelium E2E envelope
    }

    /// recipient -> sequence -> message
    mapping(address => mapping(uint256 => Message)) private _msgs;
    /// recipient -> next sequence
    mapping(address => uint256) private _seq;

    /// Store an E2E-encrypted envelope for `to`. Reverts if the envelope is
    /// empty (no point storing nothing). Emits Inbox.
    /// @param to   recipient address
    /// @param data mycelium E2E envelope (kind || eph_pub || nonce || ciphertext)
    function deliver(address to, bytes calldata data) external returns (uint256) {
        require(to != address(0), "mailbox: no zero recipient");
        require(data.length > 0, "mailbox: empty payload");
        uint256 seq = _seq[to]++;
        _msgs[to][seq] = Message({
            from: msg.sender,
            blockNumber: block.number,
            data: data
        });
        emit Inbox(to, msg.sender, seq, _hash(data));
        return seq;
    }

    /// Read a specific message. Only the recipient (or anyone — data is
    /// already E2E-encrypted, so reading is not a privacy leak; but we
    /// restrict to recipient for cleanliness) may read.
    function read(address to, uint256 seq) external view returns (address from, uint256 blockNumber, bytes memory data) {
        require(msg.sender == to, "mailbox: only recipient");
        Message storage m = _msgs[to][seq];
        return (m.from, m.blockNumber, m.data);
    }

    /// Total messages stored for a recipient (to know seq range to poll).
    function length(address to) external view returns (uint256) {
        return _seq[to];
    }

    /// Burn a message (compost semantics: content should rot). Sets the stored
    /// data to empty so it no longer exists. Only recipient.
    function burn(address to, uint256 seq) external {
        require(msg.sender == to, "mailbox: only recipient");
        _msgs[to][seq].data = "";
    }

    function _hash(bytes memory d) private pure returns (bytes32) {
        return keccak256(d);
    }
}
