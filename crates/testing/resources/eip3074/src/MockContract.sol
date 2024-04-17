// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

contract MockContract {
    event Message(address sender, string message);

    function sendMessage(string calldata message) external {
        emit Message(msg.sender, message);
    }
}
