use num_traits::One;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry, ORIGINAL_TRACE_IDX};

use super::{PoseidonRelation, LOG_EXPAND, N_STATE, RATE, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS};
use super::{apply_external_round_matrix, apply_internal_round_matrix, pow5_expr, EXTERNAL_ROUND_CONSTS, INTERNAL_ROUND_CONSTS};

/// Evaluator for Poseidon Computing component
///
/// This component computes Poseidon hash for n_active_messages, with padding rows afterward.
/// It yields the final_state (16 elements) ONLY at target_message row via LogUp.
///
/// Trace columns (ORIGINAL_TRACE_IDX):
/// - Columns 0-7: message (RATE=8 elements)
/// - Columns 8-23: initial_state (N_STATE=16 elements)
/// - Columns 24-...: intermediate states (full rounds + partial rounds)
/// - Columns ...-end: final_state (N_STATE=16 elements)
///
/// Constraints:
/// 1. First row: capacity must be zero (initial_state[8..16] = 0)
/// 2. Transition constraints (chaining between rows) - masked by is_active * (1 - is_first)
/// 3. Poseidon permutation correctness - masked by is_active
/// 4. LogUp: yields final_state ONLY at target_message row (multiplicity = is_target)
#[derive(Clone)]
pub struct PoseidonComputingEval {
    pub log_n_rows: u32,
    pub n_active_messages: usize,
    pub poseidon_relation: PoseidonRelation,
    pub claimed_sum: SecureField,
    pub is_first_id: PreProcessedColumnId,
    pub is_active_id: PreProcessedColumnId,  // 1 for rows 0..=target_message, 0 for rest
    pub is_target_id: PreProcessedColumnId,  // 1 only for target_message row (for LogUp)
}

impl FrameworkEval for PoseidonComputingEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + LOG_EXPAND
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_first_val = eval.get_preprocessed_column(self.is_first_id.clone());
        let is_active_val = eval.get_preprocessed_column(self.is_active_id.clone());
        let is_target_val = eval.get_preprocessed_column(self.is_target_id.clone());

        // Read message (8 elements) - current row only
        let message: [E::F; RATE] = std::array::from_fn(|_| {
            let [curr, _prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
            curr
        });

        // Read initial state (16 elements) - current and previous row
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

        // Constraint 1: First row capacity must be zero
        for i in RATE..N_STATE {
            eval.add_constraint(is_first_val.clone() * initial_state_curr[i].clone());
        }

        // Constraint 2: Transition constraints (chaining between rows)
        // CRITICAL: Only enabled for active rows (excluding first row)
        // Padding rows (is_active = 0) have chaining DISABLED for isolation
        let enable_chaining = is_active_val.clone() * (E::F::one() - is_first_val.clone());

        // Rate part: initial_state[0..8] = final_state_prev[0..8] + message[0..8]
        for i in 0..RATE {
            let expected = final_state_prev[i].clone() + message[i].clone();
            eval.add_constraint(enable_chaining.clone() * (initial_state_curr[i].clone() - expected));
        }

        // Capacity part: initial_state[8..16] = final_state_prev[8..16]
        for i in RATE..N_STATE {
            eval.add_constraint(
                enable_chaining.clone() * (initial_state_curr[i].clone() - final_state_prev[i].clone()),
            );
        }

        // Constraint 3: Poseidon permutation correctness
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
                    is_active_val.clone() * (state[i].clone() - intermediate_full1[round][i].clone()),
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
                state[i] =
                    state[i].clone() + E::F::from(EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i]);
            }
            apply_external_round_matrix(&mut state);
            state = std::array::from_fn(|i| pow5_expr(state[i].clone()));

            // Verify intermediate state matches trace (masked by is_active)
            for i in 0..N_STATE {
                eval.add_constraint(
                    is_active_val.clone() * (state[i].clone() - intermediate_full2[round][i].clone()),
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

        // LogUp: yield final_state ONLY for target_message row
        // This allows Scheduler to verify it's using the correct Poseidon hash result
        eval.add_to_relation(RelationEntry::new(
            &self.poseidon_relation,
            is_target_val.into(),    // multiplicity: 1 only for target_message, 0 for rest
            &final_state_curr,       // yield all 16 elements of final_state
        ));

        eval.finalize_logup_in_pairs();

        eval
    }
}

pub type PoseidonComputingComponent = FrameworkComponent<PoseidonComputingEval>;
