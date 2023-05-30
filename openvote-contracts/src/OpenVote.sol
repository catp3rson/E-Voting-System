// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract OpenVote {
    // constants

    // This address should be changed to Ethereum address of aggregator
    address constant public STARK_VERIFIER = address(uint160(uint256(keccak256("StarkOpenVote"))));
    // Size of Rescue digest (in bytes)
    uint256 constant public BYTES_PER_DIGEST = 56;
    // Size of Cheetah point (in bytes)
    uint256 constant public BYTES_PER_AFFINE = 96;
    // Fee to participate is 0.005 ether
    uint256 constant public FEE_UNIT = 5000000000000000;

    // paramaters

    address public aggregatorAddr;
    uint256[5] public timeStamps;
    bytes public elgRoot;
    bytes public generator;

    // state variables

    // index of current phase of election
    uint256 public guard = 0;
    // number of registered voters
    uint256 public numRegisteredVoters = 0;
    // serialized valid encrypted votes
    bytes public encryptedVotes;
    // deposit made by each voter
    mapping(address => uint256) public deposit;
    // mapping from address and its partially registered voting key
    mapping(address => bytes) public parVotingKeys;
    // mapping from registered voting key and its address
    mapping(bytes => address) public addresses;
    // list of registered addresses
    address[] public registeredAddrs;
    // result of the election
    uint256 public electionResult;

    // events

    event IndexAssigned(address indexed voterAddr, uint256 idx);

    // modifiers

    modifier onlyAggregator {
        require(msg.sender == aggregatorAddr, "Unauthorized sender.");
        _;
    }

    constructor(uint256[5] memory _timeStamps, bytes memory _elgRoot, bytes memory _generator) payable {
        // validate timestamps
        require(block.number < _timeStamps[0] &&
            _timeStamps[0] < _timeStamps[1] &&
            _timeStamps[1] < _timeStamps[2] &&
            _timeStamps[2] < _timeStamps[3] &&
            _timeStamps[3] < _timeStamps[4],
            "Timestamps are not in correct order."
        );
        require(msg.value == FEE_UNIT, "Incorrect fee.");
        require(guard == 0, "Prohibited by guard.");
        require(_elgRoot.length == BYTES_PER_DIGEST, "Incorrect length of elgRoot.");
        
        // check generator
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(
            bytes.concat(abi.encodeWithSignature("checkGenerator(bytes)"), _generator)
        );
        require(success, "Call to checkGenerator failed.");
        bool validGenerator = abi.decode(response, (bool));
        require(validGenerator, "Generator is not valid.");

        // store parameters
        timeStamps[0] = _timeStamps[0];
        timeStamps[1] = _timeStamps[1];
        timeStamps[2] = _timeStamps[2];
        timeStamps[3] = _timeStamps[3];
        timeStamps[4] = _timeStamps[4];
        elgRoot = _elgRoot;
        generator = _generator;
        aggregatorAddr = msg.sender;

        // confirm that aggregator has sent correct fee
        deposit[msg.sender] = 1;

        // update guard
        guard = 1;
    }

    function registerVoters(bytes calldata registerProof) public onlyAggregator {
        require(block.number >= timeStamps[0] && block.number < timeStamps[1], "Incorrect time frame.");
        require(guard == 1, "Prohibited by guard.");

        // verifyRegister(bytes,bytes)
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(
            bytes.concat(hex"f35a2913", elgRoot, registerProof)
        );
        require(success, "Call to verifyRegister failed.");
        (bool validRegister, uint256 numParReg) = abi.decode(response, (bool, uint256));
        require(validRegister, "All registrations must all be valid.");
        uint256 keyEnd = 4 + BYTES_PER_AFFINE * numParReg;
        uint256 keyOffset = 4;
        uint256 addrOffset = keyEnd;

        // map address to partially registered voting key
        while (keyOffset < keyEnd) {
            parVotingKeys[address(bytes20(registerProof[addrOffset: addrOffset + 20]))] 
                = registerProof[keyOffset: keyOffset + BYTES_PER_AFFINE];
            unchecked {
                addrOffset += 20;
                keyOffset += BYTES_PER_AFFINE;
            }
        }

        // update guard
        guard = 2;
    }

    function registerConfirm() public payable {
        require(block.number >= timeStamps[1] && block.number < timeStamps[2], "Incorrect time frame.");
        require(msg.value == FEE_UNIT, "Incorrect fee.");
        require(guard == 2, "Prohibited by guard.");
        require(parVotingKeys[msg.sender].length == BYTES_PER_AFFINE, "msg.sender is not partially registered.");
        bytes storage votingKey = parVotingKeys[msg.sender];
        require(addresses[votingKey] == address(0x0), "This voting key has already been registered.");
        // update state variables
        deposit[msg.sender] = 1;
        registeredAddrs.push(msg.sender);
        addresses[votingKey] = msg.sender;
        emit IndexAssigned(msg.sender, numRegisteredVoters++);
    }

    function castVotes(bytes calldata castProof) public payable onlyAggregator {
        require(block.number >= timeStamps[2] && block.number < timeStamps[3], "Incorrect time frame.");
        require(guard == 2, "Prohibited by guard."); 
        bytes memory votingKeys;
        uint256 vkeysNBytes = numRegisteredVoters * BYTES_PER_AFFINE;

        assembly {
            mstore(votingKeys, vkeysNBytes)
        }

        for ((uint256 i, uint256 j) = (0, 0x20); i < numRegisteredVoters; ) {
            bytes memory votingKey = parVotingKeys[registeredAddrs[i]];
            assembly {
                mstore(add(votingKeys, j), mload(add(votingKey, 0x20)))
                mstore(add(votingKeys, add(j, 0x20)), mload(add(votingKey, 0x40)))
                mstore(add(votingKeys, add(j, 0x40)), mload(add(votingKey, 0x60)))
            }
            unchecked {
                ++i;
                j += BYTES_PER_AFFINE;
            }
        }

        // verifyCast(bytes,bytes)
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(
            bytes.concat(
                hex"c7414cec", bytes4(uint32(numRegisteredVoters)), votingKeys, castProof
            )
        );
        require(success, "Call to verifyCast failed.");
        (bool validCast, bytes memory outputs) = abi.decode(response, (bool, bytes));
        require(outputs.length == numRegisteredVoters, "Length of outputs does not match numRegisteredVoters.");

        for (uint256 i = 0; i < numRegisteredVoters; ) {
            if (outputs[i] == 0x0) {
                // penalize voter with valid vote
                validCast = false;
                deposit[registeredAddrs[i]] = 0;
            }
            unchecked {
                ++i;
            }
        }

        require(validCast, "All registered voters must cast valid votes.");

        // store encrypted votes
        encryptedVotes = castProof[: 4 + BYTES_PER_AFFINE * numRegisteredVoters];

        // update guard
        guard = 3;
    }

    function voteTallying(uint256 tallyResult) public onlyAggregator {
        require(block.number >= timeStamps[3] && block.number < timeStamps[4], "Incorrect time frame.");
        require(guard == 3, "Prohibited by guard.");
        
        // verifyTally(uint256,bytes)
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(
            bytes.concat(
                hex"9754bb37", bytes4(uint32(tallyResult)), encryptedVotes
            )
        );
        require(success, "Call to verifyTally failed.");
        bool validResult = abi.decode(response, (bool));
        require(validResult, "Tally result is not valid.");

        electionResult = tallyResult;
        guard = 4;
    }

    function refund() public {
        require(block.number >= timeStamps[4], "Incorrect time frame.");
        require(deposit[msg.sender] == 1, "Deposit was seized or not received.");
        deposit[msg.sender] = 0;
        payable(msg.sender).transfer(FEE_UNIT);
    }
}