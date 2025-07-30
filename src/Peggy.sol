// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

struct ValsetArgs {
    address[] validators;
    uint256[] powers;
    uint256 valsetNonce;
    uint256 rewardAmount;
    address rewardToken;
}

contract Peggy {
    bytes32 public state_peggyId;
    uint256 public state_powerThreshold;
    uint256 public state_lastValsetNonce;
    mapping(bytes32 => bool) public state_lastValsetCheckpoint;
    mapping(address => uint256) public state_lastBatchNonces;

    event ValsetUpdatedEvent(
        uint256 indexed valsetNonce,
        address[] validators,
        uint256[] powers
    );

    event TransactionBatchExecutedEvent(
        uint256 indexed batchNonce,
        address indexed token,
        uint256 eventNonce
    );

    constructor() {
        // Empty constructor - initialization happens in initialize()
    }

    function initialize(
        bytes32 _peggyId,
        uint256 _powerThreshold,
        address[] memory _validators,
        uint256[] memory _powers
    ) public {
        require(_validators.length == _powers.length, "Mismatched validators and powers");
        
        // Set state variables
        state_peggyId = _peggyId;
        state_powerThreshold = _powerThreshold;
        
        bytes32 newCheckpoint = makeCheckpoint(
            ValsetArgs(_validators, _powers, 0, 0, address(0)),
            _peggyId
        );
        state_lastValsetCheckpoint[newCheckpoint] = true;
    }

    function makeCheckpoint(
        ValsetArgs memory _valsetArgs,
        bytes32 _peggyId
    ) public pure returns (bytes32) {
        // Create a checkpoint hash of the valset data
        bytes32 methodName = keccak256("checkpoint");
        
        bytes32 checkpoint = keccak256(
            abi.encode(
                methodName,
                _peggyId,
                _valsetArgs.valsetNonce,
                _valsetArgs.validators,
                _valsetArgs.powers,
                _valsetArgs.rewardAmount,
                _valsetArgs.rewardToken
            )
        );
        
        return checkpoint;
    }

    function updateValset(
        ValsetArgs memory _newValset,
        ValsetArgs memory _currentValset,
        uint8[] memory _v,
        bytes32[] memory _r,
        bytes32[] memory _s
    ) public {
        // Verify current valset checkpoint
        bytes32 currentCheckpoint = makeCheckpoint(_currentValset, state_peggyId);
        require(
            state_lastValsetCheckpoint[currentCheckpoint],
            "Supplied current validators and powers do not match checkpoint."
        );

        // Create new checkpoint
        bytes32 newCheckpoint = makeCheckpoint(_newValset, state_peggyId);
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", newCheckpoint));

        // **VULNERABILITY**: The power calculation doesn't check for duplicate validators!
        // This allows an attacker to duplicate their address in the validator set
        // and have their power counted multiple times
        uint256 cumulativePower = 0;
        
        for (uint256 i = 0; i < _currentValset.validators.length; i++) {
            if (_v[i] != 0) {
                address signer = ecrecover(digest, _v[i], _r[i], _s[i]);
                
                // Find the signer's power in the current valset
                for (uint256 j = 0; j < _currentValset.validators.length; j++) {
                    if (_currentValset.validators[j] == signer) {
                        cumulativePower += _currentValset.powers[j];
                        break;
                    }
                }
            }
        }

        require(
            cumulativePower >= state_powerThreshold,
            "Insufficient power to update valset"
        );

        // Update state
        state_lastValsetCheckpoint[currentCheckpoint] = false;
        state_lastValsetCheckpoint[newCheckpoint] = true;
        state_lastValsetNonce = _newValset.valsetNonce;

        emit ValsetUpdatedEvent(_newValset.valsetNonce, _newValset.validators, _newValset.powers);
    }

    function submitBatch(
        ValsetArgs memory _currentValset,
        uint8[] memory _v,
        bytes32[] memory _r,
        bytes32[] memory _s,
        uint256[] memory _amounts,
        address[] memory _destinations,
        uint256[] memory _fees,
        uint256 _batchNonce,
        address _tokenContract,
        uint256 _batchTimeout
    ) public {
        // Verify current valset checkpoint
        bytes32 currentCheckpoint = makeCheckpoint(_currentValset, state_peggyId);
        require(
            state_lastValsetCheckpoint[currentCheckpoint],
            "Supplied current validators and powers do not match checkpoint."
        );

        // Create batch digest
        bytes32 batchHash = keccak256(
            abi.encode(
                state_peggyId,
                0x7472616e73616374696f6e426174636800000000000000000000000000000000, // "transactionBatch"
                _amounts,
                _destinations,
                _fees,
                _batchNonce,
                _tokenContract,
                _batchTimeout
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", batchHash));

        // **VULNERABILITY**: Same issue as updateValset - power calculation doesn't check for duplicates!
        // If the current valset has duplicate validators (from a previous malicious update),
        // an attacker can provide the same signature multiple times and have their power counted multiple times
        uint256 cumulativePower = 0;
        
        for (uint256 i = 0; i < _currentValset.validators.length; i++) {
            if (_v[i] != 0) {
                address signer = ecrecover(digest, _v[i], _r[i], _s[i]);
                
                // Find the signer's power in the current valset
                // **BUG**: If the valset has duplicates, this will count the same validator's power multiple times
                for (uint256 j = 0; j < _currentValset.validators.length; j++) {
                    if (_currentValset.validators[j] == signer) {
                        cumulativePower += _currentValset.powers[j];
                        break;
                    }
                }
            }
        }

        require(
            cumulativePower >= state_powerThreshold,
            "Insufficient power to submit batch"
        );

        // Execute transfers
        IERC20 token = IERC20(_tokenContract);
        for (uint256 i = 0; i < _amounts.length; i++) {
            token.transfer(_destinations[i], _amounts[i]);
        }

        // Update nonce
        state_lastBatchNonces[_tokenContract] = _batchNonce;

        emit TransactionBatchExecutedEvent(_batchNonce, _tokenContract, 0);
    }
}
