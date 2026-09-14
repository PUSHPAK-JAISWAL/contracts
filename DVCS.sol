// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DVCS - decentralized version control system
/// @notice on-chain source of truth for repositories, conmmits, branches and 
/// tags. Actual file contents are not stored on chain( that would be prohibitively expensive);
/// instread each commit stores:
/// - "treeroot": a keccat255 merkel rot of the tracked file tree,
/// computed client-side, while lets anyone
/// verify a downloaded snapshot matches what are commited.
/// - "cid": a content identifier (e.g. an iPFS cid) pointing at the offchain ojectbundle
///for that commit
/// everything that defines "history and permission " -who
/// committed what, when 
contract DVCS {
    
}
