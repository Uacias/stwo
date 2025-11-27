use num_traits::One;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry, ORIGINAL_TRACE_IDX,
};

use super::{
    apply_external_round_matrix, apply_internal_round_matrix, pow5_expr, MerkleRelation,
    EXTERNAL_ROUND_CONSTS, INTERNAL_ROUND_CONSTS, LOG_EXPAND, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS,
    N_STATE,
};

/// Evaluator for Merkle Computing component (KKRT STYLE)
///
/// This component computes a Merkle path verification using KKRT Labs approach:
/// - Each node is a SINGLE M31 value
/// - Each level uses ONE row with hash input [left, right, 0, ..., 0]
/// - Hash output is ONLY state[0] after Poseidon2 permutation
/// - It yields the final computed root (1 element) ONLY at the last row via LogUp.
///
/// Trace columns (ORIGINAL_TRACE_IDX):
/// - Columns 0-15: initial_state (N_STATE=16 elements) = [left, right, 0, 0, ..., 0]
///   * initial_state[0] = left child
///   * initial_state[1] = right child
///   * initial_state[2..15] = 0 (implicit capacity = 0)
/// - Columns 16-...: intermediate states (full rounds + partial rounds)
/// - Columns ...-157: final_state (N_STATE=16 elements) - hash result
/// - Column 158: index_bit (0 or 1) - determines position of current node
///
/// Constraints (KKRT - single permutation per level):
/// 1. Initial state constraint: initial_state[2..16] must be zero (implicit capacity)
/// 2. Chaining constraint (for rows 1..depth): final_state_prev[0] must appear in
///    initial_state[0] or initial_state[1] based on index_bit
/// 3. Poseidon2 permutation correctness - masked by is_active
/// 4. LogUp: yields final_state[0] (computed root, 1 element) ONLY at last row (multiplicity = is_last)
#[derive(Clone)]
pub struct MerkleComputingEval {
    pub log_n_rows: u32,
    pub depth: usize, // Tree depth (number of active hash computations = depth rows)
    pub merkle_relation: MerkleRelation,
    pub claimed_sum: SecureField,
    pub is_first_id: PreProcessedColumnId,
    pub is_active_id: PreProcessedColumnId, // 1 for rows 0..depth, 0 for padding
    pub is_last_id: PreProcessedColumnId,   // 1 only for row (depth-1), for LogUp
}

impl FrameworkEval for MerkleComputingEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + LOG_EXPAND
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_first_val = eval.get_preprocessed_column(self.is_first_id.clone());
        let is_active_val = eval.get_preprocessed_column(self.is_active_id.clone());
        let is_last_val = eval.get_preprocessed_column(self.is_last_id.clone());

        // KKRT: NO message columns - initial_state contains [left, right, 0, ..., 0] directly

        // Read initial state (16 elements) - current row only
        let initial_state_curr: [E::F; N_STATE] = std::array::from_fn(|_| {
            let [curr, _prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
            curr
        });

        // Read intermediate states from first 4 full rounds
        let intermediate_full1: [[E::F; N_STATE]; N_HALF_FULL_ROUNDS] = std::array::from_fn(|_| {
            std::array::from_fn(|_| {
                let [curr, _prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
                curr
            })
        });

        // Read partial round intermediate states
        let intermediate_partial: [E::F; N_PARTIAL_ROUNDS] = std::array::from_fn(|_| {
            let [curr, _prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
            curr
        });

        // Read intermediate states from last 4 full rounds
        let intermediate_full2: [[E::F; N_STATE]; N_HALF_FULL_ROUNDS] = std::array::from_fn(|_| {
            std::array::from_fn(|_| {
                let [curr, _prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
                curr
            })
        });

        // Read final state (16 elements) - current and PREVIOUS row
        let mut final_state_curr_vec = Vec::with_capacity(N_STATE);
        let mut final_state_prev_vec = Vec::with_capacity(N_STATE);
        for _ in 0..N_STATE {
            let [curr, prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
            final_state_curr_vec.push(curr);
            final_state_prev_vec.push(prev);
        }
        let final_state_curr: [E::F; N_STATE] =
            std::array::from_fn(|i| final_state_curr_vec[i].clone());
        let final_state_prev: [E::F; N_STATE] =
            std::array::from_fn(|i| final_state_prev_vec[i].clone());

        // Read index_bit (1 element) - current row only
        // index_bit = 0: current node is on left (initial_state[0])
        // index_bit = 1: current node is on right (initial_state[1])
        let [index_bit_curr, _index_bit_prev] =
            eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);

        // KKRT Constraint 1: Implicit capacity must be zero
        // initial_state[2..16] = 0 (elements after left and right children)
        // This ensures the KKRT format: [left, right, 0, 0, ..., 0]
        for i in 2..N_STATE {
            eval.add_constraint(is_active_val.clone() * initial_state_curr[i].clone());
        }

        // KKRT Constraint 2: Chaining constraint
        // For rows 1..depth (not first row): final_state_prev[0] must be in current row's input
        // If index_bit = 0: current node on left  -> initial_state[0] = final_state_prev[0]
        // If index_bit = 1: current node on right -> initial_state[1] = final_state_prev[0]
        //
        // Combined constraint (enabled for non-first active rows):
        // (1 - index_bit) * (initial_state[0] - final_state_prev[0]) = 0  (when index_bit=0)
        // index_bit * (initial_state[1] - final_state_prev[0]) = 0        (when index_bit=1)
        let not_first = E::F::one() - is_first_val.clone();
        let enable_chaining = is_active_val.clone() * not_first;

        // When index_bit = 0: current node is on left, so initial_state[0] = prev_hash
        let one_minus_index_bit = E::F::one() - index_bit_curr.clone();
        eval.add_constraint(
            enable_chaining.clone()
                * one_minus_index_bit
                * (initial_state_curr[0].clone() - final_state_prev[0].clone()),
        );

        // When index_bit = 1: current node is on right, so initial_state[1] = prev_hash
        eval.add_constraint(
            enable_chaining
                * index_bit_curr.clone()
                * (initial_state_curr[1].clone() - final_state_prev[0].clone()),
        );

        // KKRT Constraint 3: index_bit must be 0 or 1 (boolean constraint)
        // index_bit * (1 - index_bit) = 0
        eval.add_constraint(
            is_active_val.clone()
                * index_bit_curr.clone()
                * (E::F::one() - index_bit_curr.clone()),
        );

        // Constraint 4: Poseidon2 permutation correctness
        // Verify that the intermediate states match the permutation computation
        // MASKED BY is_active: Only enforce for active rows
        let mut state = initial_state_curr.clone();

        // 4 full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..N_STATE {
                state[i] = state[i].clone() + E::F::from(EXTERNAL_ROUND_CONSTS[round][i]);
            }
            apply_external_round_matrix(&mut state);
            state = std::array::from_fn(|i| pow5_expr(state[i].clone()));

            // Verify intermediate state matches trace (masked by is_active)
            for i in 0..N_STATE {
                eval.add_constraint(
                    is_active_val.clone()
                        * (state[i].clone() - intermediate_full1[round][i].clone()),
                );
            }
            state = intermediate_full1[round].clone();
        }

        // Partial rounds
        for round in 0..N_PARTIAL_ROUNDS {
            state[0] = state[0].clone() + E::F::from(INTERNAL_ROUND_CONSTS[round]);
            apply_internal_round_matrix(&mut state);
            state[0] = pow5_expr(state[0].clone());

            // Verify intermediate state matches trace (masked by is_active)
            eval.add_constraint(
                is_active_val.clone() * (state[0].clone() - intermediate_partial[round].clone()),
            );
            state[0] = intermediate_partial[round].clone();
        }

        // 4 full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..N_STATE {
                state[i] = state[i].clone()
                    + E::F::from(EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i]);
            }
            apply_external_round_matrix(&mut state);
            state = std::array::from_fn(|i| pow5_expr(state[i].clone()));

            // Verify intermediate state matches trace (masked by is_active)
            for i in 0..N_STATE {
                eval.add_constraint(
                    is_active_val.clone()
                        * (state[i].clone() - intermediate_full2[round][i].clone()),
                );
            }
            state = intermediate_full2[round].clone();
        }

        // Verify final state matches computed state (masked by is_active)
        for i in 0..N_STATE {
            eval.add_constraint(
                is_active_val.clone() * (state[i].clone() - final_state_curr[i].clone()),
            );
        }

        // KKRT LogUp: yield computed_root (ONLY state[0]) for last row
        // This allows Scheduler to verify it's using the correct Merkle root
        // KKRT style: We yield only state[0] (1 element) as the hash output
        let root_value = final_state_curr[0].clone();

        eval.add_to_relation(RelationEntry::new(
            &self.merkle_relation,
            is_last_val.into(), // multiplicity: 1 only for last row (root computation), 0 for rest
            &[root_value],      // KKRT: yield only state[0] (1 element) - the computed root
        ));

        eval.finalize_logup_in_pairs();

        eval
    }
}

pub type MerkleComputingComponent = FrameworkComponent<MerkleComputingEval>;
