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
/// committed what, when , on top of which parent(s), who is allowed to push, and what
//and what a branch/tag currently points at -- lives on chain
// and is therefore tamper eveident and indpendent of any single server.
contract DVCS {
  //limits 
  
  /// @notice maximum bytes of (possibly encrypted) payload allowed in a 
  //singel pushBlob chuck call. Kept comfortably below typical
  //block gas and transaction size limits so no single chuck
  //transaction is ever at risk of being dropped or failing
  //becausse of its own size --large files are split into more 
  //chunks instead of bigger ones. Each chuck is also its own
  //indpendent, immediately confirmed transaction, so if a 
  //push is interrupted ( or one chuck,s transaction fails),
  //every chuck that already landed on chain stays there 
  //nothing already confirmed is lost, only what hadn't been sent yet
  //needs to be retried (the CLI's local changelog and
  //'blob Announced" check make that resumable').
  uint256 public constant MAX_CHUNK_BYTES = 24_576;
  
  /// @notice sanity bound on how many chunk a single blob may be split
  //into, keeping client-side reconstruction bounded even for
  //unexpectedly large files(24kb*4096 =~ 96MB ceiling/blob).
  uint256 public constant MAX_CHUNK_PER_BLOB = 4096;

}
