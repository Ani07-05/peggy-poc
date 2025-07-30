// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

// This is a simplified version of the custom contract used by the project.
// It provides the necessary function for the PoC to compile and run.
contract OwnableUpgradeableWithExpiry is Initializable, OwnableUpgradeable {
    function __Ownable_init_unchained() internal onlyInitializing {
        __Ownable_init(msg.sender);
    }
}
