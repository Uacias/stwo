use num_traits::One;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry, ORIGINAL_TRACE_IDX};

use super::{MerkleRelation, LOG_EXPAND, RATE};

/// Evaluator for Merkle Scheduler component
///
/// This component uses (consumes) the computed_root from the Merkle Computing component
/// and verifies it matches the expected_root (public input).
///
/// Trace columns (ORIGINAL_TRACE_IDX):
/// - Columns 0-7: computed_root (8 elements from Computing component)
/// - Columns 8-15: expected_root (8 elements, public input)
///
/// Constraints:
/// 1. computed_root == expected_root (element-wise equality for all 8 elements, all rows)
/// 2. Transition constraints: values are constant across rows (both values same in all rows)
/// 3. LogUp: uses computed_root ONLY in first row (multiplicity = -is_first)
///
/// All rows have the same constant values.
#[derive(Clone)]
pub struct MerkleSchedulerEval {
    pub log_n_rows: u32,
    pub merkle_relation: MerkleRelation,
    pub claimed_sum: SecureField,
    pub is_first_id: PreProcessedColumnId,
}

impl FrameworkEval for MerkleSchedulerEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + LOG_EXPAND
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_first = eval.get_preprocessed_column(self.is_first_id.clone());

        // Read computed_root (8 elements) - current and previous row
        let mut computed_root_curr_vec = Vec::with_capacity(RATE);
        let mut computed_root_prev_vec = Vec::with_capacity(RATE);
        for _ in 0..RATE {
            let [curr, prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
            computed_root_curr_vec.push(curr);
            computed_root_prev_vec.push(prev);
        }
        let computed_root_curr: [E::F; RATE] = std::array::from_fn(|i| computed_root_curr_vec[i].clone());
        let computed_root_prev: [E::F; RATE] = std::array::from_fn(|i| computed_root_prev_vec[i].clone());

        // Read expected_root (8 elements) - current and previous row
        let mut expected_root_curr_vec = Vec::with_capacity(RATE);
        let mut expected_root_prev_vec = Vec::with_capacity(RATE);
        for _ in 0..RATE {
            let [curr, prev] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
            expected_root_curr_vec.push(curr);
            expected_root_prev_vec.push(prev);
        }
        let expected_root_curr: [E::F; RATE] = std::array::from_fn(|i| expected_root_curr_vec[i].clone());
        let expected_root_prev: [E::F; RATE] = std::array::from_fn(|i| expected_root_prev_vec[i].clone());

        // Constraint 1: computed_root == expected_root (for all rows, element-wise)
        // This is the main Merkle verification constraint
        for i in 0..RATE {
            eval.add_constraint(
                computed_root_curr[i].clone() - expected_root_curr[i].clone()
            );
        }

        // Constraint 2: Transition constraints - values are constant across rows
        // Disabled for first row
        let not_first = E::F::one() - is_first.clone();

        for i in 0..RATE {
            eval.add_constraint(not_first.clone() * (computed_root_curr[i].clone() - computed_root_prev[i].clone()));
            eval.add_constraint(not_first.clone() * (expected_root_curr[i].clone() - expected_root_prev[i].clone()));
        }

        // LogUp: Use computed_root ONLY in first row (multiplicity = -is_first)
        // This "consumes" the value that Computing component "yielded"
        eval.add_to_relation(RelationEntry::new(
            &self.merkle_relation,
            (-is_first.clone()).into(), // multiplicity: -1 for row 0, 0 for rest
            &computed_root_curr,         // use value from Computing component
        ));

        eval.finalize_logup_in_pairs();

        eval
    }
}

pub type MerkleSchedulerComponent = FrameworkComponent<MerkleSchedulerEval>;
