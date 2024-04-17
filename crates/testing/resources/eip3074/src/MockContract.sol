// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

contract MockContract {
    address public lastSender;

    function recordSender() external {
        lastSender = msg.sender;
    }
}
