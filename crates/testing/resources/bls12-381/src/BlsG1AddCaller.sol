// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

contract BlsG1AddCaller {
     function call (bytes calldata _input) external returns (bytes memory _output) {
         address precompile = address(0x0B);
         (bool ok, bytes memory output) = precompile.call(_input);
         require(ok);
         _output = output;
     }
 }
