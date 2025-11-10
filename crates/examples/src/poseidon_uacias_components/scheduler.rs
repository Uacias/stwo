use num_traits::One;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry, ORIGINAL_TRACE_IDX};

use super::{PoseidonRelation, LOG_EXPAND, N_STATE};

/// Evaluator for Poseidon Scheduler component
///
/// This component uses (consumes) final_state values from two Poseidon Computing components
/// and combines them (element-wise addition).
///
/// Trace columns (ORIGINAL_TRACE_IDX):
/// - Columns 0-15: poseidon1_final_state (16 elements from Computing1)
/// - Columns 16-31: poseidon2_final_state (16 elements from Computing2)
/// - Columns 32-47: combined_state (element-wise sum: poseidon1 + poseidon2)
///
/// Constraints:
/// 1. combined_state[i] = poseidon1_final_state[i] + poseidon2_final_state[i] (for all rows, all i)
/// 2. Transition constraints: values are constant across rows
/// 3. LogUp: uses both final_state values ONLY in first row (multiplicity = -is_first)
///
/// All rows have the same constant values (like Fibonacci Scheduler).
#[derive(Clone)]
pub struct PoseidonSchedulerEval {
    pub log_n_rows: u32,
    pub poseidon_relation: PoseidonRelation,
    pub claimed_sum: SecureField,
    pub is_first_id: PreProcessedColumnId,
}

impl FrameworkEval for PoseidonSchedulerEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + LOG_EXPAND
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_first = eval.get_preprocessed_column(self.is_first_id.clone());

        // Read poseidon1_final_state (16 elements) - current and previous row
        let mut poseidon1_curr_vec = Vec::with_capacity(N_STATE);
        let mut poseidon1_prev_vec = Vec::with_capacity(N_STATE);
        for _ in 0..N_STATE {
            let [curr, prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
            poseidon1_curr_vec.push(curr);
            poseidon1_prev_vec.push(prev);
        }
        let poseidon1_curr: [E::F; N_STATE] = std::array::from_fn(|i| poseidon1_curr_vec[i].clone());
        let poseidon1_prev: [E::F; N_STATE] = std::array::from_fn(|i| poseidon1_prev_vec[i].clone());

        // Read poseidon2_final_state (16 elements) - current and previous row
        let mut poseidon2_curr_vec = Vec::with_capacity(N_STATE);
        let mut poseidon2_prev_vec = Vec::with_capacity(N_STATE);
        for _ in 0..N_STATE {
            let [curr, prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
            poseidon2_curr_vec.push(curr);
            poseidon2_prev_vec.push(prev);
        }
        let poseidon2_curr: [E::F; N_STATE] = std::array::from_fn(|i| poseidon2_curr_vec[i].clone());
        let poseidon2_prev: [E::F; N_STATE] = std::array::from_fn(|i| poseidon2_prev_vec[i].clone());

        // Read combined_state (16 elements) - current and previous row
        let mut combined_curr_vec = Vec::with_capacity(N_STATE);
        let mut combined_prev_vec = Vec::with_capacity(N_STATE);
        for _ in 0..N_STATE {
            let [curr, prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
            combined_curr_vec.push(curr);
            combined_prev_vec.push(prev);
        }
        let combined_curr: [E::F; N_STATE] = std::array::from_fn(|i| combined_curr_vec[i].clone());
        let combined_prev: [E::F; N_STATE] = std::array::from_fn(|i| combined_prev_vec[i].clone());

        // Constraint 1: combined_state = poseidon1_final_state + poseidon2_final_state (for all rows)
        // Element-wise addition for all 16 elements
        for i in 0..N_STATE {
            eval.add_constraint(
                combined_curr[i].clone() - (poseidon1_curr[i].clone() + poseidon2_curr[i].clone())
            );
        }

        // Constraint 2: Transition constraints - values are constant across rows
        // Disabled for first row
        let not_first = E::F::one() - is_first.clone();

        for i in 0..N_STATE {
            eval.add_constraint(not_first.clone() * (poseidon1_curr[i].clone() - poseidon1_prev[i].clone()));
            eval.add_constraint(not_first.clone() * (poseidon2_curr[i].clone() - poseidon2_prev[i].clone()));
            eval.add_constraint(not_first.clone() * (combined_curr[i].clone() - combined_prev[i].clone()));
        }

        // LogUp: Use both final_state values ONLY in first row (multiplicity = -is_first)
        // This "consumes" the values that Computing components "yielded"
        eval.add_to_relation(RelationEntry::new(
            &self.poseidon_relation,
            (-is_first.clone()).into(), // multiplicity: -1 for row 0, 0 for rest
            &poseidon1_curr,            // use value from Computing1
        ));

        eval.add_to_relation(RelationEntry::new(
            &self.poseidon_relation,
            (-is_first.clone()).into(), // multiplicity: -1 for row 0, 0 for rest
            &poseidon2_curr,            // use value from Computing2
        ));

        eval.finalize_logup_in_pairs();

        eval
    }
}

pub type PoseidonSchedulerComponent = FrameworkComponent<PoseidonSchedulerEval>;
