// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/OpenVote.sol";

contract OpenVoteTest is Test {
    // constants

    address constant public STARK_VERIFIER = address(uint160(uint256(keccak256("StarkOpenVote"))));
    uint256 constant public BYTES_PER_DIGEST = 56;
    uint256 constant public BYTES_PER_AFFINE = 96;
    uint256 constant public FEE_UNIT = 5000000000000000;
    
    // parameters

    OpenVote public openVoteContract;
    address[] voterAddrs;
    bytes[] votingKeys;
    
    function testCheckGeneratorValid() public view {
        bytes memory generator = vm.readFileBinary("artifacts/generator.dat");
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(
            bytes.concat(abi.encodeWithSignature("checkGenerator(bytes)"), generator)
        );
        require(success, "Call to checkGenerator should succeed.");
        bool validGenerator = abi.decode(response, (bool));
        require(validGenerator, "Generator should be valid.");
    }

    function testCheckGeneratorInvalid() public view {
        bytes memory generator = vm.readFileBinary("artifacts/generator.dat");
        generator[16] ^= hex"01";
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(
            bytes.concat(abi.encodeWithSignature("checkGenerator(bytes)"), generator)
        );
        require(success, "Call to checkGenerator should succeed.");
        bool validGenerator = abi.decode(response, (bool));
        require(!validGenerator, "Generator should be invalid.");
    }

    function testCheckGeneratorTooShort() public view {
        bytes memory generator = vm.readFileBinary("artifacts/generator.dat");
        assembly {
            mstore(generator, sub(mload(generator), 1))
        }
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(
            bytes.concat(abi.encodeWithSignature("checkGenerator(bytes)"), generator)
        );
        require(!success, "Call to checkGenerator should fail.");
    }

    function testCheckGeneratorTooLong() public view {
        bytes memory generator = vm.readFileBinary("artifacts/generator.dat");
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(
            bytes.concat(abi.encodeWithSignature("checkGenerator(bytes)"), bytes.concat(generator, hex"01"))
        );
        require(!success, "Call to checkGenerator should fail.");
    }

    function testRegisterValidProof() public view {
        bytes memory sentData = vm.readFileBinary("artifacts/register_proof.dat");
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(sentData);
        require(success, "Call to verifyRegister should succeed.");
        (bool validRegister, uint256 numParReg) = abi.decode(response, (bool, uint256));
        require(validRegister, "Register proof should be valid.");
        require(numParReg == 2, "Returned no. partially registered voters should match test data.");
    }

    function testRegisterCorruptedProof() public view {
        bytes memory sentData = vm.readFileBinary("artifacts/register_proof.dat");
        sentData[420] ^= hex"01";
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(sentData);
        require(success, "Call to verifyRegister should succeed.");
        (bool validRegister, uint256 numParReg) = abi.decode(response, (bool, uint256));
        require(!validRegister, "Register proof should be invalid.");
    }

    function testRegisterProofTooShort() public view {
        bytes memory sentData = vm.readFileBinary("artifacts/register_proof.dat");
        bool success;
        address addr = STARK_VERIFIER;
        assembly {
            success := staticcall(gas(), addr, add(sentData, 32), sub(mload(sentData), 420), 0x80, 0)
        }
        require(!success, "Call to verifyRegister should fail.");
    }

    function testRegisterProofTooLong() public view {
        bytes memory sentData = vm.readFileBinary("artifacts/register_proof.dat");
        bool success;
        address addr = STARK_VERIFIER;
        bool validRegister;
        uint256 numParReg;
        assembly {
            success := staticcall(gas(), addr, add(sentData, 32), add(mload(sentData), 420), 0x80, 0)
            returndatacopy(0x80, 0, 64)
            validRegister := mload(0x80)
            numParReg := mload(add(0x80, 32))
        }
        require(success, "Call to verifyRegister should succeed.");
        require(validRegister, "Register proof should be valid.");
        require(numParReg == 2, "Returned no. partially registered voters should match test data.");
    }

    function testCastValidProof() public view {
        bytes memory sentData = vm.readFileBinary("artifacts/cast_proof.dat");
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(sentData);
        require(success, "Call to verifyCast should succeed.");
        (bool validCast, bytes memory outputs) = abi.decode(response, (bool, bytes));
        require(validCast, "Cast proof should be valid.");
        require(outputs.length == 2, "Returned outputs should have length that matches test data.");
        require(outputs[0] == hex"01" && outputs[1] == hex"01", "Returned outputs should have values that match test data.");
    }

    function testCastCorruptedProof() public view {
        bytes memory sentData = vm.readFileBinary("artifacts/cast_proof.dat");
        sentData[420] ^= hex"01";
        (bool success, bytes memory response) = STARK_VERIFIER.staticcall(sentData);
        require(success, "Call to verifyCast should succeed.");
        (bool validCast, bytes memory outputs) = abi.decode(response, (bool, bytes));
        require(!validCast, "Cast proof should be invalid.");
    }

    function testCastProofTooShort() public view {
        bytes memory sentData = vm.readFileBinary("artifacts/cast_proof.dat");
        bool success;
        address addr = STARK_VERIFIER;
        assembly {
            success := staticcall(gas(), addr, add(sentData, 32), sub(mload(sentData), 420), 0x80, 0)
        }
        require(!success, "Call to verifyCast should fail.");
    }

    function testCastProofTooLong() public view {
        bytes memory sentData = vm.readFileBinary("artifacts/cast_proof.dat");
        bool success;
        address addr = STARK_VERIFIER;
        bytes memory response;
        assembly {
            success := staticcall(gas(), addr, add(sentData, 32), add(mload(sentData), 420), 0x80, 0)
            mstore(response, returndatasize())
            returndatacopy(add(response, 0x20), 0, returndatasize())
        }
        require(success, "Call to verifyRegister should succeed.");
        (bool validCast, bytes memory outputs) = abi.decode(response, (bool, bytes));
        require(validCast, "Cast proof should be valid.");
        require(outputs.length == 2, "Returned outputs should have length that matches test data.");
        require(outputs[0] == hex"01" && outputs[1] == hex"01", "Returned outputs should have values that match test data.");
    }

    function _testConstructor() public {
        vm.roll(1);
        uint256[5] memory timeStamps = [uint256(5), uint256(10), uint256(15), uint256(20), uint256(25)];
        bytes memory elgRoot = vm.readFileBinary("artifacts/elg_root.dat");
        bytes memory generator = vm.readFileBinary("artifacts/generator.dat");
        openVoteContract = new OpenVote{value: FEE_UNIT}(timeStamps, elgRoot, generator);
        for (uint256 i = 0; i < 5; ++i) {
            require(openVoteContract.timeStamps(i) == timeStamps[i], "timeStamps should be set.");
        }
        require(keccak256(openVoteContract.elgRoot()) == keccak256(elgRoot), "elgRoot should be set.");
        require(keccak256(openVoteContract.generator()) == keccak256(generator), "generator should be set.");
        require(openVoteContract.aggregatorAddr() == address(this), "aggregatorAddr should be set.");
        require(openVoteContract.deposit(address(this)) == 1, "deposit should be received.");
        require(openVoteContract.guard() == 1, "guard should be updated.");
    }

    function _testRegisterVoters() public {
        vm.roll(6);
        bytes memory registerProof = vm.readFileBinary("artifacts/truncated_register_proof.dat");
        openVoteContract.registerVoters(registerProof);
        bytes memory votingKey;
        bytes32 voterAddrBytes;
        address voterAddr;
        uint256 votingKeyNBytes = BYTES_PER_AFFINE;

        assembly {
            mstore(votingKey, votingKeyNBytes)
        }

        for ((uint256 i, uint j) = (0x24, 0xe4); i < 0x24 + 2 * BYTES_PER_AFFINE;) {
            assembly {
                mstore(add(votingKey, 0x20), mload(add(registerProof, i)))
                mstore(add(votingKey, 0x40), mload(add(registerProof, add(i, 0x20))))
                mstore(add(votingKey, 0x60), mload(add(registerProof, add(i, 0x40))))
                voterAddrBytes := mload(add(registerProof, j))
            }
            voterAddr = address(bytes20(voterAddrBytes));
            voterAddrs.push(voterAddr);
            votingKeys.push(votingKey);
            require(keccak256(openVoteContract.parVotingKeys(voterAddr)) == keccak256(votingKey), "votingKey should be correctly stored.");
            unchecked {
                i += BYTES_PER_AFFINE;
                j += 20;
            }
        }
        
        require(openVoteContract.guard() == 2, "guard should be updated.");
    }
    
    function _testConfirmRegister() public {
        vm.roll(11);
        for (uint256 i = 0; i < voterAddrs.length; ++i) {
            payable(voterAddrs[i]).transfer(FEE_UNIT * 2);
            vm.prank(voterAddrs[i]);
            openVoteContract.registerConfirm{value: FEE_UNIT}();
            require(openVoteContract.deposit(voterAddrs[i]) == 1, "Deposit should be received.");
            require(openVoteContract.addresses(votingKeys[i]) == voterAddrs[i], "addresses map should be set.");
        }
    }

    function _testCastVotes() public {
        vm.roll(16);
        bytes memory castProof = vm.readFileBinary("artifacts/truncated_cast_proof.dat");
        openVoteContract.castVotes(castProof);
        bytes memory encryptedVotes;
        uint256 votesNBytes = 2 * BYTES_PER_AFFINE;
        assembly {
            mstore(encryptedVotes, add(votesNBytes, 4))
        }
        for (uint256 i = 0x20; i <= 0x20 + votesNBytes;) {
            assembly {
                mstore(add(encryptedVotes, i), mload(add(castProof, i)))
                mstore(add(encryptedVotes, add(i, 0x20)), mload(add(castProof, add(i, 0x20))))
                mstore(add(encryptedVotes, add(i, 0x40)), mload(add(castProof, add(i, 0x40))))
            }
            unchecked {
                i += BYTES_PER_AFFINE;
            }
        }
        require(keccak256(encryptedVotes) == keccak256(openVoteContract.encryptedVotes()), "Encrypted votes should be stored.");
        require(openVoteContract.guard() == 3, "guard should be updated.");
    }

    function _testVoteTallying() public {
        vm.roll(21);
        uint256 tallyResult = uint256(uint32(bytes4(vm.readFileBinary("artifacts/tally_result.dat"))));
        openVoteContract.voteTallying(tallyResult);
        require(openVoteContract.electionResult() == tallyResult, "Tally result should be stored.");
        require(openVoteContract.guard() == 4, "guard should be updated.");
    }

    function _testRefund() public {
        vm.roll(26);
        for (uint256 i = 0; i < voterAddrs.length; ) {
            require(openVoteContract.deposit(voterAddrs[i]) == 1, "Deposit should be received.");
            vm.prank(voterAddrs[i]);
            openVoteContract.refund();
            require(openVoteContract.deposit(voterAddrs[i]) == 0, "Deposit should be transferred back.");
            unchecked {
                ++i;
            }
        }
    }

    function testIntegration() public {
        _testConstructor();
        _testRegisterVoters();
        _testConfirmRegister();
        _testCastVotes();
        _testVoteTallying();
        _testRefund();
    }
}

