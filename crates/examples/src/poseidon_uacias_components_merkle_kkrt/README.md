# KKRT Labs Style Merkle Tree Verification

This module implements Merkle tree verification using the **KKRT Labs approach** from their [cairo-m repository](https://github.com/KKRT-labs/cairo-m).

## Overview

The KKRT style provides significant efficiency improvements over the standard sponge-based Merkle implementation by simplifying the hash structure and reducing proof sizes.

## Key Differences from Standard Implementation

### 1. Node Representation
- **KKRT**: Each node is a **single M31 field element**
- **Standard**: Each node is 8 M31 elements (full RATE)
- **Result**: 8x smaller node size, 8x smaller proofs

### 2. Hash Computation
- **KKRT**: Single Poseidon2 permutation with input `[left, right, 0, 0, ..., 0]` → output is `state[0]`
- **Standard**: Sequential absorption: absorb(left) → absorb(right) → extract state[0..8]
- **Result**: Simpler computation, no capacity management between levels

### 3. Rows per Tree Level
- **KKRT**: 1 row per level
- **Standard**: 2 rows per level (one for each absorption)
- **Result**: 2x fewer trace rows

### 4. Column Counts (depth=2 example)
```
Computing Component:
  KKRT:     174 columns (no message columns)
  Standard: 182 columns (8 message + 174 others)

Scheduler Component:
  KKRT:     2 columns   (1 computed + 1 expected root)
  Standard: 16 columns  (8 computed + 8 expected root)

Total Reduction: 22 fewer columns
```

## Implementation Details

### Trace Structure

#### Computing Component
Proves that a Merkle path is correctly computed using Poseidon2.

**Columns (174 total):**
- `initial_state[16]`: Input state `[left, right, 0, ..., 0]`
- `intermediate_full1[4×16]`: First 4 full rounds
- `intermediate_partial[14]`: 14 partial rounds
- `intermediate_full2[4×16]`: Last 4 full rounds
- `final_state[16]`: Output state (only `state[0]` is used as hash)

**Constraints:**
1. Implicit capacity = 0: `initial_state[2..16] == 0`
2. Poseidon2 permutation correctness (masked by `is_active`)
3. LogUp: yields `final_state[0]` for last row only

#### Scheduler Component
Verifies that the computed root matches the expected public root.

**Columns (2 total):**
- `computed_root`: Single M31 value from Computing component
- `expected_root`: Public input (single M31 value)

**Constraints:**
1. `computed_root == expected_root` (all rows)
2. Transition constraints: values constant across rows
3. LogUp: consumes `computed_root` in first row

### Preprocessed Columns
- `is_first`: 1 for row 0, 0 elsewhere
- `is_active`: 1 for rows [0..depth), 0 elsewhere
- `is_level_start`: 1 for all active rows (KKRT: each row is a level)
- `is_last`: 1 for row (depth-1), 0 elsewhere

### LogUp Mechanism
The LogUp argument links Computing and Scheduler:
- Computing **yields** the computed root (multiplicity = +1 at last row)
- Scheduler **uses** the computed root (multiplicity = -1 at first row)
- Total sum must be 0 for consistency

## Usage Example

```rust
use poseidon_uacias_components_merkle_kkrt::*;

// Generate a tree of depth 3 (8 leaves)
let tree = generate_merkle_tree(3, 100);

// Get siblings for leaf at index 5
let leaf_index = 5;
let siblings = tree.get_siblings(leaf_index);

// Setup prover
let config = PcsConfig::default();
let channel = &mut Blake2sChannel::default();
let twiddles = SimdBackend::precompute_twiddles(
    CanonicCoset::new(16).circle_domain().half_coset
);
let commitment_scheme = CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(
    config,
    &twiddles
);

// Generate proof
let (proof, _, _, statement0, statement1) = prove_merkle(
    tree.depth,
    tree.leaves[leaf_index],
    siblings,
    leaf_index as u32,
    tree.root,
    channel,
    commitment_scheme,
)?;

// Verify proof
verify_merkle(proof, tree.depth, statement0, statement1, config)?;
```

## Helper Functions

### `generate_merkle_tree(depth: usize, start_value: u32) -> MerkleTree`
Generates a complete Merkle tree with sequential leaf values.

**Returns:**
```rust
struct MerkleTree {
    depth: usize,
    leaves: Vec<BaseField>,
    levels: Vec<Vec<BaseField>>, // levels[0] = leaves, levels[depth] = root
    root: BaseField,
}
```

**Methods:**
- `get_siblings(leaf_index) -> Vec<BaseField>`: Get sibling nodes for proof
- `verify_path(leaf_index) -> bool`: Local verification without STARK

### `hash_two_nodes_kkrt(left: BaseField, right: BaseField) -> BaseField`
Computes KKRT-style hash: single Poseidon2 permutation on `[left, right, 0, ..., 0]`.

## Running Tests

```bash
# Run all tests
cargo test --package stwo-examples --lib poseidon_uacias_components_merkle_kkrt

# Run specific test
cargo test --package stwo-examples --lib test_kkrt_simple -- --nocapture

# Show implementation info
cargo test --package stwo-examples --lib test_kkrt_info -- --nocapture
```

## Test Coverage

- ✅ `test_kkrt_simple`: Depth 2 (4 leaves) - basic functionality
- ✅ `test_kkrt_depth_3`: Depth 3 (8 leaves)
- ✅ `test_kkrt_depth_4`: Depth 4 (16 leaves)
- ✅ `test_kkrt_multiple_indices`: Multiple proofs for same tree
- ✅ `test_kkrt_info`: Implementation comparison and stats
- ⏭️ `test_kkrt_depth_5`: Depth 5 (32 leaves) - ignored, needs larger twiddles config

## Performance Benefits

1. **Smaller Proofs**: 8x reduction in node size
2. **Fewer Columns**: ~11% reduction in total columns
3. **Simpler Logic**: No capacity management, single permutation per level
4. **Better Efficiency**: 2x fewer trace rows per tree level

## References

- KKRT Labs cairo-m: https://github.com/KKRT-labs/cairo-m
- Poseidon2 Hash: https://eprint.iacr.org/2023/323
- Circle STARKs (stwo): https://github.com/starkware-libs/stwo

## Implementation Status

✅ **Complete and Tested**
- All core functionality implemented
- Comprehensive test suite
- LogUp verification working
- End-to-end proof generation and verification

## Files

- `mod.rs`: Main module with prove/verify functions and tests
- `computing.rs`: Computing component (Merkle path computation)
- `scheduler.rs`: Scheduler component (root verification)
- `trace_gen.rs`: Trace generation for both components
- `README.md`: This documentation

---

**Author**: Implementation based on KKRT Labs approach
**Framework**: Starkware stwo Circle STARK prover
**Date**: 2025-01
