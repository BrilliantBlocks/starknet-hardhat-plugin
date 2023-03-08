// SPDX-License-Identifier: MIT
// Superset of OpenZeppelin Contracts for Cairo v0.6.1 (upgrades/presets/Proxy.cairo) by BrilliantBlocks

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import (
    library_call,
    library_call_l1_handler,
    replace_class,
    get_caller_address,
    get_contract_address,
)

from contract_src.OpenZeppelinAccount.library import Proxy

// @dev Cairo doesn't support native decoding like Solidity yet,
//      that's why we pass three arguments for calldata instead of one
// @param implementation_hash the implementation contract hash
// @param selector the implementation initializer function selector
// @param calldata_len the calldata length for the initializer
// @param calldata an array of felt containing the raw calldata
@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    implementation_hash: felt, selector: felt, calldata_len: felt, calldata: felt*
) {
    alloc_locals;
    Proxy._set_implementation_hash(implementation_hash);

    if (selector != 0) {
        // Initialize proxy from implementation
        library_call(
            class_hash=implementation_hash,
            function_selector=selector,
            calldata_size=calldata_len,
            calldata=calldata,
        );
    }

    return ();
}

//
// Fallback functions
//

@external
@raw_input
@raw_output
func __default__{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    selector: felt, calldata_size: felt, calldata: felt*
) -> (retdata_size: felt, retdata: felt*) {
    let (class_hash) = Proxy.get_implementation_hash();

    let (retdata_size: felt, retdata: felt*) = library_call(
        class_hash=class_hash,
        function_selector=selector,
        calldata_size=calldata_size,
        calldata=calldata,
    );
    return (retdata_size, retdata);
}

@l1_handler
@raw_input
func __l1_default__{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    selector: felt, calldata_size: felt, calldata: felt*
) {
    let (class_hash) = Proxy.get_implementation_hash();

    library_call_l1_handler(
        class_hash=class_hash,
        function_selector=selector,
        calldata_size=calldata_size,
        calldata=calldata,
    );
    return ();
}

// @dev Upgrade the proxy and support migration to Cairo v1
// @param class_hash of the upgraded contract
@external
func upgrade{syscall_ptr: felt*}(class_hash: felt) {
    assert_only_self();
    replace_class(class_hash);
    return ();
}

func assert_only_self{syscall_ptr: felt*}() {
    let (caller) = get_caller_address();
    let (self) = get_contract_address();
    assert caller = self;
    return ();
}
