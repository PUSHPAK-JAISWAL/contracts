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
  
  //types 

  enum Role {
    None,// no access 0 
    Reader,// 1 - can be tracked as explicit member of a privat repo
    Contributor,// 2 can push commits, create branch/tags
    Maintainer // 2 can also force update/delete branches, manage,collaborators
  }

  struct Commit{
    bytes32 parent1; // for the root commit
    bytes32 parent2; // non-zero only for merge commits
    bytes32 treeRoot; //Merkle root of the commited file tree
    string cid; // off chain content identifier
    string message; //commit message
    address author; // msg.sender that authored teh commit
    uint64 timestamp; // block.timestamp at commit time 
    bool exists;
  }

  struct Repository {
    address owner;
    string name;
    bool isPrivate;
    bool exists;
    uint256 commitCount;
    uint8 minApprovals; // pr need at least this many approvals to merge
    mapping(bytes32 => Commit) commits;
    mapping(string => bytes32) branchHead;
    mapping(string => bool) branchExists;
    string[] branchNames;
    mapping(string => bytes32) tags;
    mapping(string => bool) tagExists;
    mapping(address => Role) roles;
    address[] collaborators;
  }

  enum PRStatus {
    Open,
    Merged,
    Closed
  }

  struct PullRequest {
    bool exists;
    string sourceBranch;
    string targetBranch;
    address author;
    string title;
    string description;
    PRStatus status;
    uint256 approvalCount;
    bytes32 mergedCommit;
    uint64 createdAt;
    mapping(address => bool) hasApproved;
  }

  // storage 
  //
  mapping(bytes32 => Repository) private repositories;
  bytes32[] public repositoryIds;

  ///@dev repoId => blobHash -> announced. a blob only needs to be 
  //pushed once even if referenced by many commits
  //this lets a pushing client cheaply check whether its
  //can skip re-uploading one.
  //
  mapping(bytes32 => mapping( bytes32 => bool)) public blobAnnounced;

  /// @dev repoid -> pr id -> PullRequest, and repoId => next pr identifier
  //also usable as how many prs exist for iteration.
  //
  mapping(bytes32 => mapping(uint256 => PullRequest)) private pullRequests;
  mapping(bytes32 => uint256) public pullRequestCount;
  
  //events 
  //
  event RepositoryCreated(bytes32 indexed repoId, address indexed owner, string name, bool isPrivate);
    event CommitPushed(bytes32 indexed repoId, bytes32 indexed commitHash, bytes32 parent1, bytes32 parent2, address indexed author, string cid);
    event BranchCreated(bytes32 indexed repoId, string branchName, bytes32 commitHash);
    event BranchUpdated(bytes32 indexed repoId, string branchName, bytes32 oldHead, bytes32 newHead, bool forced);
    event BranchDeleted(bytes32 indexed repoId, string branchName);
    event TagCreated(bytes32 indexed repoId, string tagName, bytes32 commitHash);
    event CollaboratorUpdated(bytes32 indexed repoId, address indexed account, Role role);
    event OwnershipTransferred(bytes32 indexed repoId, address indexed previousOwner, address indexed newOwner);
    event VisibilityChanged(bytes32 indexed repoId, bool isPrivate);

    event PullRequestOpened(
        bytes32 indexed repoId, uint256 indexed prId, address indexed author, string sourceBranch, string targetBranch, string title
    );
    event PullRequestApproved(bytes32 indexed repoId, uint256 indexed prId, address indexed approver, uint256 approvalCount);
    event PullRequestMerged(bytes32 indexed repoId, uint256 indexed prId, bytes32 mergedCommit, address indexed merger);
    event PullRequestClosed(bytes32 indexed repoId, uint256 indexed prId, address indexed closer);

    /// @notice One chunk of a blob's (possibly encrypted) content. Emitting
    ///         data as an event rather than writing it to contract storage
    ///         keeps this cheap (~16 gas/byte instead of ~20000 gas per 32
    ///         bytes for SSTORE), while still being permanent and readable
    ///         by any client via eth_getLogs -- no IPFS or other off-chain
    ///         service required. NOTE: event data is still public on-chain;
    ///         `encrypted` only tells readers whether `data` is ciphertext,
    ///         it does not restrict who can read it.
    event BlobChunk(
        bytes32 indexed repoId,
        bytes32 indexed blobHash,
        uint32 chunkIndex,
        uint32 totalChunks,
        bool encrypted,
        bytes data
    );

  //errors 
    //
  error RepositoryAlreadyExists();
    error RepositoryNotFound();
    error NotAuthorized();
    error CommitAlreadyExists();
    error CommitNotFound();
    error ParentCommitNotFound();
    error BranchAlreadyExists();
    error BranchNotFound();
    error TagAlreadyExists();
    error TagNotFound();
    error NotFastForward();
    error InvalidName();
    error ZeroAddress();
    error InvalidChunk();
    error ChunkTooLarge();
    error TooManyChunks();
    error PRNotFound();
    error PRNotOpen();
    error CannotApproveOwnPR();
    error AlreadyApproved();
    error NotEnoughApprovals();
  
  //modifiers 
    //
  modifier repoExists(bytes32 repoId) {
        if (!repositories[repoId].exists) revert RepositoryNotFound();
        _;
    }

    /// @dev Contributor or higher (or the owner) may push commits / create branches & tags.
    modifier onlyContributor(bytes32 repoId) {
        Repository storage r = repositories[repoId];
        if (msg.sender != r.owner && r.roles[msg.sender] < Role.Contributor) revert NotAuthorized();
        _;
    }

    /// @dev Maintainer or higher (or the owner) may force-push, delete branches, manage collaborators.
    modifier onlyMaintainer(bytes32 repoId) {
        Repository storage r = repositories[repoId];
        if (msg.sender != r.owner && r.roles[msg.sender] < Role.Maintainer) revert NotAuthorized();
        _;
    }

    modifier onlyOwner(bytes32 repoId) {
        if (repositories[repoId].owner != msg.sender) revert NotAuthorized();
        _;
    }

  //identity registry
    //
  //repo owners often don't know a collaborator's raw 0x address 
    //this lets an account claim a human readable handle (an email 
    //address is a natural choice, but any string works) so others can 
    //refere to they by that instead. Claiming a handle is a transaction
    //from the account begin claimed for, so a handle to address pointing
    //is cryptographically signed by that address own key nobody 
    //else can claim a handle "as" your address 
    //
    // this proves address ownership not inbox ownership 
    // nothing here verifies that the string you register is an email 
    // address you actually control that would require an off chain
    // verifier briding email to chain, 
    // whis is a different kind of system that a smart contract can be on its own.
    // treat a handle as a claimed nickname bound to a key,
    // the same trust level as a git commit's author field useful for
    // humans, not a substitute for verifying identity out of band before 
    // you grant someone a role.
    //
    mapping(string => address) public handleOwner; // handle => address (address(0) if unclaimed)
    mapping(address => string) public addressHandle; // address => their current handle ("" if none)

    error HandleTaken();
    error HandleNotFound();
    error NoHandleRegistered();

    event HandleRegistered(address indexed account, string handle);
    event HandleReleased(address indexed account, string handle);

    /// @notice Claim `handle` for msg.sender. If msg.sender already holds a
    ///         different handle, it is released first (one handle per
    ///         address at a time). Reverts if someone else already holds
    ///         this handle.
    function registerHandle(string calldata handle) external {
        if (bytes(handle).length == 0) revert InvalidName();
        address current = handleOwner[handle];
        if (current != address(0) && current != msg.sender) revert HandleTaken();

        string memory old = addressHandle[msg.sender];
        if (bytes(old).length > 0) {
            delete handleOwner[old];
        }
        handleOwner[handle] = msg.sender;
        addressHandle[msg.sender] = handle;
        emit HandleRegistered(msg.sender, handle);
    }

    /// @notice Release msg.sender's currently registered handle, if any.
    function releaseHandle() external {
        string memory old = addressHandle[msg.sender];
        if (bytes(old).length == 0) revert NoHandleRegistered();
        delete handleOwner[old];
        delete addressHandle[msg.sender];
        emit HandleReleased(msg.sender, old);
    }

    /// @notice Look up the address currently holding `handle`. Reverts if
    ///         unclaimed, so callers can distinguish "not found" from
    ///         "found, address(0)" without an extra existence flag.
    function resolveHandle(string calldata handle) external view returns (address) {
        address a = handleOwner[handle];
        if (a == address(0)) revert HandleNotFound();
        return a;
    }

    // repo managment
    //
    /// @notice Deterministically derive a repository id from its creator and name,
    ///         so a given (owner, name) pair can only ever be created once.
    function computeRepoId(address owner, string calldata name) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, name));
    }

    function createRepository(string calldata name, bool isPrivate) external returns (bytes32 repoId) {
        if (bytes(name).length == 0) revert InvalidName();
        repoId = computeRepoId(msg.sender, name);
        Repository storage r = repositories[repoId];
        if (r.exists) revert RepositoryAlreadyExists();

        r.owner = msg.sender;
        r.name = name;
        r.isPrivate = isPrivate;
        r.exists = true;

        repositoryIds.push(repoId);
        emit RepositoryCreated(repoId, msg.sender, name, isPrivate);
    }

    function transferOwnership(bytes32 repoId, address newOwner) external repoExists(repoId) onlyOwner(repoId) {
        if (newOwner == address(0)) revert ZeroAddress();
        Repository storage r = repositories[repoId];
        address previous = r.owner;
        r.owner = newOwner;
        emit OwnershipTransferred(repoId, previous, newOwner);
    }

    function setVisibility(bytes32 repoId, bool isPrivate) external repoExists(repoId) onlyOwner(repoId) {
        repositories[repoId].isPrivate = isPrivate;
        emit VisibilityChanged(repoId, isPrivate);
    }

  // Access control
    //
    function setCollaboratorRole(byte32 repoId, address account, Role role)
      external
      repoExists(repoId)
      onlyMaintainer(repoId)
      {
        if(account == address(0)) revert ZeroAddress();
        Repository storage r = reppositories[repoId];
        if(r.roles[account] == Role.None && role != Role.None) {
          r.collaborators.push(account);
        }
        r.roles[account] = role;
        emit CollaboratorUpdated(repoId,account,role);
    }

    function roleOf(bytes32 repoId, address account) external view repoExists(repoId) {
      Repository storage r = repositories[repoId];
      if(account == r.owner) return Role.Maintainer;
      return r.roles[account];
    }

    function collaborators(bytes32 repoId) external view repoExists(repoId) returns(address[] memory) {
      return repositories[repoId].collaborators;
    }

    
}
