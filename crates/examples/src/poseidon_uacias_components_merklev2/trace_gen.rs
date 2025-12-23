use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::{LogupTraceGenerator, Relation};

use super::{
    apply_external_round_matrix, apply_internal_round_matrix, pow5, PoseidonRelation,
    EXTERNAL_ROUND_CONSTS, FULL_ROUNDS, INTERNAL_ROUND_CONSTS, N_COLUMNS, N_HALF_FULL_ROUNDS,
    N_PARTIAL_ROUNDS, N_STATE, RATE,
};

/// Generate trace for Poseidon Computing component
///
/// Returns (trace columns, target_final_state)
/// - trace: N_COLUMNS columns (message + initial_state + intermediates + final_state)
/// - target_final_state: the final_state at target_message row (BEFORE bit-reversal)
///
/// Generates Poseidon hashes only up to n_active_messages (inclusive), rest are padding zeros.
///
/// # Arguments
/// * `log_size` - Log2 of total number of rows
/// * `n_active_messages` - Number of active messages to hash (rest are padding)
/// * `messages` - Vector of messages (each RATE=8 elements)
///
/// # Returns
/// * Trace columns (bit-reversed)
/// * target_final_state: final_state at row (n_active_messages - 1) before bit-reversal
pub fn gen_poseidon_computing_trace(
    log_size: u32,
    n_active_messages: usize,
    messages: Vec<[BaseField; RATE]>,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    [BaseField; N_STATE],
) {
    let n_rows = 1 << log_size;

    // Extend messages to fill all rows if needed
    let mut extended_messages = messages;
    while extended_messages.len() < n_rows {
        extended_messages.push([BaseField::from_u32_unchecked(0); RATE]);
    }

    let mut trace = (0..N_COLUMNS)
        .map(|_| Col::<SimdBackend, BaseField>::zeros(n_rows))
        .collect::<Vec<_>>();

    let mut prev_output: Option<[BaseField; N_STATE]> = None;
    let mut target_final_state = [BaseField::from_u32_unchecked(0); N_STATE];

    for row in 0..n_rows {
        let mut col_index = 0;
        let is_padding_row = row >= n_active_messages;

        // For padding rows: use zero message
        let message = if is_padding_row {
            [BaseField::from_u32_unchecked(0); RATE]
        } else {
            extended_messages[row]
        };

        // Write message columns (8 elements)
        for i in 0..RATE {
            trace[col_index].set(row, message[i]);
            col_index += 1;
        }

        // Compute initial state
        let mut state: [BaseField; N_STATE] = if !is_padding_row && prev_output.is_some() {
            // Not first row AND not padding: state = [prev_rate + message, prev_capacity]
            let prev = prev_output.unwrap();
            std::array::from_fn(|i| {
                if i < RATE {
                    prev[i] + message[i]
                } else {
                    prev[i]
                }
            })
        } else {
            // First row OR padding row: state = [message, zeros] (no chaining)
            let new_state = if is_padding_row {
                // Padding row: completely zero initial state
                [BaseField::from_u32_unchecked(0); N_STATE]
            } else {
                // First row: state = [message, zeros]
                std::array::from_fn(|i| {
                    if i < RATE {
                        message[i]
                    } else {
                        BaseField::from_u32_unchecked(0)
                    }
                })
            };
            new_state
        };

        // Write initial state columns (16 elements)
        for i in 0..N_STATE {
            trace[col_index].set(row, state[i]);
            col_index += 1;
        }

        // For padding rows: skip Poseidon computation, set intermediate and final states to zeros
        if is_padding_row {
            // Intermediate states for first 4 full rounds: all zeros
            for _ in 0..N_HALF_FULL_ROUNDS {
                for _ in 0..N_STATE {
                    trace[col_index].set(row, BaseField::from_u32_unchecked(0));
                    col_index += 1;
                }
            }

            // Partial rounds intermediate states: all zeros
            for _ in 0..N_PARTIAL_ROUNDS {
                trace[col_index].set(row, BaseField::from_u32_unchecked(0));
                col_index += 1;
            }

            // Intermediate states for last 4 full rounds: all zeros
            for _ in 0..N_HALF_FULL_ROUNDS {
                for _ in 0..N_STATE {
                    trace[col_index].set(row, BaseField::from_u32_unchecked(0));
                    col_index += 1;
                }
            }

            // Final state: all zeros
            for _ in 0..N_STATE {
                trace[col_index].set(row, BaseField::from_u32_unchecked(0));
                col_index += 1;
            }
        } else {
            // Active row: compute Poseidon permutation normally
            // 4 full rounds
            (0..N_HALF_FULL_ROUNDS).for_each(|round| {
                (0..N_STATE).for_each(|i| {
                    state[i] += EXTERNAL_ROUND_CONSTS[round][i];
                });
                apply_external_round_matrix(&mut state);
                state = std::array::from_fn(|i| pow5(state[i]));
                state.iter().for_each(|&s| {
                    trace[col_index].set(row, s);
                    col_index += 1;
                });
            });

            // Partial rounds
            (0..N_PARTIAL_ROUNDS).for_each(|round| {
                state[0] += INTERNAL_ROUND_CONSTS[round];
                apply_internal_round_matrix(&mut state);
                state[0] = pow5(state[0]);
                trace[col_index].set(row, state[0]);
                col_index += 1;
            });

            // 4 full rounds
            (0..N_HALF_FULL_ROUNDS).for_each(|round| {
                (0..N_STATE).for_each(|i| {
                    state[i] += EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i];
                });
                apply_external_round_matrix(&mut state);
                state = std::array::from_fn(|i| pow5(state[i]));
                state.iter().for_each(|&s| {
                    trace[col_index].set(row, s);
                    col_index += 1;
                });
            });

            // Write final state columns (16 elements)
            for &s in state.iter() {
                trace[col_index].set(row, s);
                col_index += 1;
            }

            // Save the final_state at target_message row (BEFORE bit-reversal)
            if row == n_active_messages - 1 {
                target_final_state = state;
            }
        }

        // Store output for next row (only for active rows)
        if !is_padding_row {
            prev_output = Some(state);
        }
    }

    // Apply bit_reverse_coset_to_circle_domain_order to trace columns
    for col in trace.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let trace = trace
        .into_iter()
        .map(|eval| CircleEvaluation::new(domain, eval))
        .collect();

    (trace, target_final_state)
}

/// Generate interaction trace for Poseidon Computing component using LogUp
///
/// Only the target_message row (= n_active_messages - 1) yields its final_state:
///   Adds: +1 / (final_state - z)  to the LogUp column for that row
///   Other rows contribute 0 (numerator=0)
///
/// This allows Scheduler to verify it's using the correct Poseidon hash result
///
/// # Arguments
/// * `trace` - Main trace columns (bit-reversed)
/// * `poseidon_relation` - LogUp relation elements
/// * `n_active_messages` - Number of active messages (target = n_active_messages - 1)
///
/// # Returns
/// * Interaction trace columns (bit-reversed)
/// * claimed_sum - LogUp claimed sum for this component
pub fn gen_poseidon_computing_interaction_trace(
    trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    poseidon_relation: &PoseidonRelation,
    n_active_messages: usize,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let log_size = trace[0].domain.log_size();
    let n_rows = 1 << log_size;

    // Target row is the last active message (0-indexed)
    let target_row = n_active_messages - 1;

    // Create selector column: 1 only for target_row, 0 for rest
    let mut selector_col = Col::<SimdBackend, BaseField>::zeros(n_rows);
    selector_col.set(target_row, BaseField::one());

    // IMPORTANT: Apply bit-reverse to match trace column ordering!
    bit_reverse_coset_to_circle_domain_order(selector_col.as_mut_slice());

    let mut logup_gen = LogupTraceGenerator::new(log_size);

    {
        let mut col_gen = logup_gen.new_col();

        // Final state columns start at: RATE + N_STATE + N_STATE*FULL_ROUNDS + N_PARTIAL_ROUNDS
        let final_state_col_start = RATE + N_STATE + N_STATE * FULL_ROUNDS + N_PARTIAL_ROUNDS;

        // For each vec_row, yield the final_state with selector masking
        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            // Read final_state (16 elements)
            let final_state_packed: [_; N_STATE] =
                std::array::from_fn(|i| trace[final_state_col_start + i].data[vec_row]);

            // Compute denominator: poseidon_relation.combine(final_state)
            let denom = poseidon_relation.combine(&final_state_packed);

            // Use selector - only target_row lane has numerator=1
            let numerator: PackedSecureField = selector_col.data[vec_row].into();

            col_gen.write_frac(vec_row, numerator, denom);
        }

        col_gen.finalize_col();
    }

    logup_gen.finalize_last()
}

/// Generate trace for Poseidon Scheduler component
///
/// Returns 3 * N_STATE = 48 columns:
/// - Columns 0-15: poseidon1_final_state (from Computing1)
/// - Columns 16-31: poseidon2_final_state (from Computing2)
/// - Columns 32-47: combined_state (element-wise sum)
///
/// All rows have the same constant values.
///
/// # Arguments
/// * `log_size` - Log2 of total number of rows
/// * `poseidon1_final_state` - Final state from Computing1 (16 elements)
/// * `poseidon2_final_state` - Final state from Computing2 (16 elements)
///
/// # Returns
/// * Trace columns (bit-reversed)
pub fn gen_poseidon_scheduler_trace(
    log_size: u32,
    poseidon1_final_state: [BaseField; N_STATE],
    poseidon2_final_state: [BaseField; N_STATE],
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let n_rows = 1 << log_size;

    // Compute combined_state: element-wise addition
    let combined_state: [BaseField; N_STATE] =
        std::array::from_fn(|i| poseidon1_final_state[i] + poseidon2_final_state[i]);

    println!("  Scheduler trace:");
    println!(
        "    poseidon1_final_state[0]: {}",
        poseidon1_final_state[0].0
    );
    println!(
        "    poseidon2_final_state[0]: {}",
        poseidon2_final_state[0].0
    );
    println!("    combined_state[0]: {}", combined_state[0].0);

    // Create 48 columns (3 * N_STATE)
    let mut columns: Vec<Col<SimdBackend, BaseField>> = Vec::with_capacity(3 * N_STATE);

    // Columns 0-15: poseidon1_final_state
    for i in 0..N_STATE {
        let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);
        for row in 0..n_rows {
            col.set(row, poseidon1_final_state[i]);
        }
        columns.push(col);
    }

    // Columns 16-31: poseidon2_final_state
    for i in 0..N_STATE {
        let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);
        for row in 0..n_rows {
            col.set(row, poseidon2_final_state[i]);
        }
        columns.push(col);
    }

    // Columns 32-47: combined_state
    for i in 0..N_STATE {
        let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);
        for row in 0..n_rows {
            col.set(row, combined_state[i]);
        }
        columns.push(col);
    }

    // Convert to bit-reversed circle domain order
    for col in columns.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    columns
        .into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect()
}

/// Generate interaction trace for Poseidon Scheduler component using LogUp
///
/// For row 0 only, uses two final_state values:
///   Adds: -1 / (poseidon1_final_state - z)  to the LogUp column
///   Adds: -1 / (poseidon2_final_state - z)  to the LogUp column
///
/// The sum of all LogUp entries from Computing1, Computing2, and Scheduler should be 0.
///
/// # Arguments
/// * `trace` - Main trace columns (bit-reversed)
/// * `poseidon_relation` - LogUp relation elements
///
/// # Returns
/// * Interaction trace columns (bit-reversed)
/// * claimed_sum - LogUp claimed sum for this component
pub fn gen_poseidon_scheduler_interaction_trace(
    trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    poseidon_relation: &PoseidonRelation,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let log_size = trace[0].domain.log_size();
    let n_rows = 1 << log_size;

    // Create is_first selector column: 1 only for row 0, 0 for rest
    let mut is_first_col = Col::<SimdBackend, BaseField>::zeros(n_rows);
    is_first_col.set(0, BaseField::one());

    // IMPORTANT: Apply bit-reverse to match trace column ordering!
    bit_reverse_coset_to_circle_domain_order(is_first_col.as_mut_slice());

    let mut logup_gen = LogupTraceGenerator::new(log_size);

    {
        let mut col_gen = logup_gen.new_col();

        // For each row, use both poseidon1_final_state (columns 0-15) and poseidon2_final_state
        // (columns 16-31) Multiplicity controlled by is_first selector (only row 0
        // contributes)
        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            // Read poseidon1_final_state (16 elements)
            let poseidon1_packed: [_; N_STATE] = std::array::from_fn(|i| trace[i].data[vec_row]);

            // Read poseidon2_final_state (16 elements)
            let poseidon2_packed: [_; N_STATE] =
                std::array::from_fn(|i| trace[N_STATE + i].data[vec_row]);

            // Compute denominators for both values
            let denom1: PackedSecureField = poseidon_relation.combine(&poseidon1_packed);
            let denom2: PackedSecureField = poseidon_relation.combine(&poseidon2_packed);

            // We need to write TWO fractions per row:
            // -1 / (poseidon1 - z) and -1 / (poseidon2 - z)
            //
            // For finalize_logup_in_pairs(), we combine them:
            // -1/denom1 + -1/denom2 = -(denom1 + denom2) / (denom1 * denom2)
            //
            // Multiplicity is controlled by is_first selector

            let is_first_value = is_first_col.data[vec_row];
            let sum: PackedSecureField = denom1 + denom2;
            let is_first_secure: PackedSecureField = is_first_value.into();
            let numerator = -(sum * is_first_secure); // -1 * (denom1+denom2) for row 0, 0 for rest
            let denominator = denom1 * denom2;

            col_gen.write_frac(vec_row, numerator, denominator);
        }

        col_gen.finalize_col();
    }

    logup_gen.finalize_last()
}

/// Generate trace for Merkle Computing component (SPONGE CONSTRUCTION)
///
/// Computes a Merkle path verification using Poseidon sponge construction.
/// Each level of the tree uses TWO rows: one to absorb each node.
/// This matches the standard Poseidon sponge with sequential absorption.
///
/// Returns (trace columns, computed_root)
/// - trace: MerkleComputing columns (message, initial_state, intermediates, final_state)
/// - computed_root: the final root hash (BEFORE bit-reversal)
///
/// # Arguments
/// * `log_size` - Log2 of total number of rows
/// * `depth` - Tree depth (number of levels in tree)
/// * `leaf` - Starting leaf value (RATE=8 elements)
/// * `siblings` - Sibling nodes for each level (length = depth, each RATE=8 elements)
/// * `index` - Leaf position in tree (determines absorption order)
///
/// # Returns
/// * Trace columns (bit-reversed)
/// * computed_root: final root hash at row (2*depth-1) before bit-reversal
///
/// # Sponge Construction
/// For each level (0..depth):
///   - Row 2*level: absorb first node (determined by index_bit)
///   - Row 2*level+1: absorb second node → produces hash for this level
/// Total active rows: 2*depth
pub fn gen_merkle_computing_trace(
    log_size: u32,
    depth: usize,
    leaf: [BaseField; RATE],
    siblings: Vec<[BaseField; RATE]>,
    index: u32,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    [BaseField; RATE],
) {
    assert_eq!(siblings.len(), depth, "siblings.len() must equal depth");

    let n_rows = 1 << log_size;
    let n_active_rows = depth * 2;
    assert!(n_active_rows <= n_rows, "2*depth must be <= n_rows");

    // Column layout (SPONGE STYLE - like poseidon_uacias_components):
    // message (8) + initial_state (16) + intermediates (4*16 + 14 + 4*16 = 142) + final_state (16)
    // = 8 + 16 + 142 + 16 = 182 columns
    const MERKLE_COMPUTING_N_COLUMNS: usize = RATE
        + N_STATE
        + (N_HALF_FULL_ROUNDS * N_STATE)
        + N_PARTIAL_ROUNDS
        + (N_HALF_FULL_ROUNDS * N_STATE)
        + N_STATE;

    let mut trace = (0..MERKLE_COMPUTING_N_COLUMNS)
        .map(|_| Col::<SimdBackend, BaseField>::zeros(n_rows))
        .collect::<Vec<_>>();

    let mut current_node = leaf;
    let mut prev_output: Option<[BaseField; N_STATE]> = None;
    let mut computed_root = [BaseField::from_u32_unchecked(0); RATE];

    for row in 0..n_rows {
        let mut col_index = 0;
        let is_padding_row = row >= n_active_rows;

        if is_padding_row {
            // Padding row: all zeros
            for _ in 0..MERKLE_COMPUTING_N_COLUMNS {
                trace[col_index].set(row, BaseField::from_u32_unchecked(0));
                col_index += 1;
            }
        } else {
            // Active row: absorb one node
            let level = row / 2; // Which tree level (0..depth)
            let is_second_absorption = (row % 2) == 1; // false = first node, true = second node
            let index_bit = (index >> level) & 1;

            // Determine which message to absorb
            let message = if !is_second_absorption {
                // First absorption: absorb left node based on index_bit
                if index_bit == 0 {
                    current_node // current on left
                } else {
                    siblings[level] // sibling on left
                }
            } else {
                // Second absorption: absorb right node based on index_bit
                if index_bit == 0 {
                    siblings[level] // sibling on right
                } else {
                    current_node // current on right
                }
            };

            // Write message (8 elements)
            for i in 0..RATE {
                trace[col_index].set(row, message[i]);
                col_index += 1;
            }

            // Compute initial_state (SPONGE CONSTRUCTION)
            // For Merkle: each level is a fresh sponge (reset capacity at start of level)
            let is_level_start = !is_second_absorption; // First absorption of each level
            let state: [BaseField; N_STATE] = if row == 0 {
                // First row: state = [message, zeros]
                let mut s = [BaseField::from_u32_unchecked(0); N_STATE];
                s[0..RATE].copy_from_slice(&message);
                s
            } else if is_level_start {
                // Start of new level: RESET capacity to zeros (fresh sponge for this level)
                let mut s = [BaseField::from_u32_unchecked(0); N_STATE];
                s[0..RATE].copy_from_slice(&message);
                s
            } else {
                // Second absorption of same level: state = [prev_rate + message, prev_capacity]
                let prev = prev_output.unwrap();
                std::array::from_fn(|i| {
                    if i < RATE {
                        prev[i] + message[i] // Absorb: XOR (add in field) message to rate
                    } else {
                        prev[i] // Capacity unchanged
                    }
                })
            };

            // Write initial_state (16 elements)
            for i in 0..N_STATE {
                trace[col_index].set(row, state[i]);
                col_index += 1;
            }

            // Compute Poseidon permutation
            let mut state = state;

            // First 4 full rounds
            for round in 0..N_HALF_FULL_ROUNDS {
                for i in 0..N_STATE {
                    state[i] = state[i] + EXTERNAL_ROUND_CONSTS[round][i];
                }
                apply_external_round_matrix(&mut state);
                state = std::array::from_fn(|i| pow5(state[i]));

                // Write intermediate state (16 elements)
                for i in 0..N_STATE {
                    trace[col_index].set(row, state[i]);
                    col_index += 1;
                }
            }

            // Partial rounds
            for round in 0..N_PARTIAL_ROUNDS {
                state[0] = state[0] + INTERNAL_ROUND_CONSTS[round];
                apply_internal_round_matrix(&mut state);
                state[0] = pow5(state[0]);

                // Write intermediate state (1 element)
                trace[col_index].set(row, state[0]);
                col_index += 1;
            }

            // Last 4 full rounds
            for round in 0..N_HALF_FULL_ROUNDS {
                for i in 0..N_STATE {
                    state[i] = state[i] + EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i];
                }
                apply_external_round_matrix(&mut state);
                state = std::array::from_fn(|i| pow5(state[i]));

                // Write intermediate state (16 elements)
                for i in 0..N_STATE {
                    trace[col_index].set(row, state[i]);
                    col_index += 1;
                }
            }

            // Write final_state (16 elements)
            for i in 0..N_STATE {
                trace[col_index].set(row, state[i]);
                col_index += 1;
            }

            // Save output for next row
            prev_output = Some(state);

            // After second absorption (odd rows), update current_node for next level
            if is_second_absorption {
                current_node.copy_from_slice(&state[0..RATE]);
            }

            // If this is the last active row, save the computed root
            if row == n_active_rows - 1 {
                computed_root.copy_from_slice(&state[0..RATE]);
            }
        }
    }

    // Apply bit-reversal to all columns
    for col in trace.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    }

    // Convert to CircleEvaluation
    let trace_cols = trace
        .into_iter()
        .map(|col| CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col))
        .collect::<Vec<_>>();

    (trace_cols, computed_root)
}

/// Generate interaction trace for Merkle Computing component (SPONGE)
///
/// Creates LogUp interaction trace that yields the computed root (8 elements)
/// ONLY at the last row (2*depth - 1).
///
/// # Arguments
/// * `trace` - The main trace columns from gen_merkle_computing_trace
/// * `merkle_relation` - The MerkleRelation for combining 8-element roots
/// * `depth` - Tree depth (determines which row is last: 2*depth - 1)
///
/// # Returns
/// * Interaction trace columns (bit-reversed)
/// * claimed_sum: The LogUp claimed sum for this component
pub fn gen_merkle_computing_interaction_trace(
    trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    merkle_relation: &super::MerkleRelation,
    log_size: u32,
    depth: usize,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let n_rows = 1 << log_size;
    let last_row = depth * 2 - 1; // Last active row in sponge construction

    // Generate is_last selector column (1 only for row 2*depth-1)
    let mut is_last_col = Col::<SimdBackend, BaseField>::zeros(n_rows);
    if depth > 0 {
        is_last_col.set(last_row, BaseField::one());
    }
    bit_reverse_coset_to_circle_domain_order(is_last_col.as_mut_slice());

    // Extract final_state columns (rate part only, 8 elements)
    // Column layout (SPONGE): message (8) + initial_state (16) + intermediates (142) + final_state
    // (16) final_state starts at column: 8 + 16 + 142 = 166
    const FINAL_STATE_START: usize = RATE
        + N_STATE
        + (N_HALF_FULL_ROUNDS * N_STATE)
        + N_PARTIAL_ROUNDS
        + (N_HALF_FULL_ROUNDS * N_STATE);

    let mut logup_gen = LogupTraceGenerator::new(log_size);

    {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            // Read final_state (rate part only - 8 elements)
            let mut final_state_rate_packed = [PackedSecureField::zero(); RATE];
            for i in 0..RATE {
                let col_data = &trace[FINAL_STATE_START + i].data;
                final_state_rate_packed[i] = col_data[vec_row].into();
            }

            // Combine using merkle_relation (8 elements)
            let denom: PackedSecureField = merkle_relation.combine(&final_state_rate_packed);

            // Multiplicity controlled by is_last selector
            let is_last_value = is_last_col.data[vec_row];
            let is_last_secure: PackedSecureField = is_last_value.into();
            let numerator = is_last_secure; // 1 for last row, 0 for rest

            col_gen.write_frac(vec_row, numerator, denom);
        }

        col_gen.finalize_col();
    }

    logup_gen.finalize_last()
}

/// Generate trace for Merkle Scheduler component
///
/// Creates a trace where all rows have the same constant values:
/// computed_root and expected_root.
///
/// # Arguments
/// * `log_size` - Log2 of total number of rows
/// * `computed_root` - The root computed by the Computing component (8 elements)
/// * `expected_root` - The expected Merkle root (public input, 8 elements)
///
/// # Returns
/// * Trace columns (bit-reversed): computed_root (8 cols) + expected_root (8 cols) = 16 total
pub fn gen_merkle_scheduler_trace(
    log_size: u32,
    computed_root: [BaseField; RATE],
    expected_root: [BaseField; RATE],
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let n_rows = 1 << log_size;

    // 16 columns: computed_root (8) + expected_root (8)
    const MERKLE_SCHEDULER_N_COLUMNS: usize = 16;

    let mut trace = (0..MERKLE_SCHEDULER_N_COLUMNS)
        .map(|_| Col::<SimdBackend, BaseField>::zeros(n_rows))
        .collect::<Vec<_>>();

    // All rows have the same values
    for row in 0..n_rows {
        let mut col_index = 0;

        // Write computed_root (8 elements)
        for i in 0..RATE {
            trace[col_index].set(row, computed_root[i]);
            col_index += 1;
        }

        // Write expected_root (8 elements)
        for i in 0..RATE {
            trace[col_index].set(row, expected_root[i]);
            col_index += 1;
        }
    }

    // Apply bit-reversal to all columns
    for col in trace.iter_mut() {
        bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());
    }

    // Convert to CircleEvaluation
    trace
        .into_iter()
        .map(|col| CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col))
        .collect::<Vec<_>>()
}

/// Generate interaction trace for Merkle Scheduler component
///
/// Creates LogUp interaction trace that uses (consumes) the computed_root
/// ONLY at the first row (multiplicity = -1).
///
/// # Arguments
/// * `trace` - The main trace columns from gen_merkle_scheduler_trace
/// * `merkle_relation` - The MerkleRelation for combining 8-element roots
/// * `log_size` - Log2 of trace size
///
/// # Returns
/// * Interaction trace columns (bit-reversed)
/// * claimed_sum: The LogUp claimed sum for this component
pub fn gen_merkle_scheduler_interaction_trace(
    trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    merkle_relation: &super::MerkleRelation,
    log_size: u32,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let n_rows = 1 << log_size;

    // Generate is_first selector column (1 only for row 0)
    let mut is_first_col = Col::<SimdBackend, BaseField>::zeros(n_rows);
    is_first_col.set(0, BaseField::one());
    bit_reverse_coset_to_circle_domain_order(is_first_col.as_mut_slice());

    // Extract computed_root columns (first 8 columns)
    let mut logup_gen = LogupTraceGenerator::new(log_size);

    {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            // Read computed_root (8 elements)
            let mut computed_root_packed = [PackedSecureField::zero(); RATE];
            for i in 0..RATE {
                let col_data = &trace[i].data;
                computed_root_packed[i] = col_data[vec_row].into();
            }

            // Combine using merkle_relation (8 elements)
            let denom: PackedSecureField = merkle_relation.combine(&computed_root_packed);

            // Multiplicity controlled by is_first selector (negative for "use")
            let is_first_value = is_first_col.data[vec_row];
            let is_first_secure: PackedSecureField = is_first_value.into();
            let numerator = -is_first_secure; // -1 for first row, 0 for rest

            col_gen.write_frac(vec_row, numerator, denom);
        }

        col_gen.finalize_col();
    }

    logup_gen.finalize_last()
}
