//! Multi-component Poseidon hash circuit with LogUp
//!
//! Architecture:
//! - PoseidonComputingComponent: Computes Poseidon hash for N messages (yields final_state via
//!   LogUp)
//! - PoseidonSchedulerComponent: Uses final_states from multiple Computing components (element-wise
//!   sum)
//!
//! Based on Poseidon2 hash function from <https://eprint.iacr.org/2023/323.pdf>

use std::ops::{Add, AddAssign, Mul, Sub};

use stwo_constraint_framework::relation;

mod computing;
mod scheduler;
mod trace_gen;

pub use computing::{PoseidonComputingComponent, PoseidonComputingEval};
use num_traits::Zero;
pub use scheduler::{PoseidonSchedulerComponent, PoseidonSchedulerEval};
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::TraceLocationAllocator;
pub use trace_gen::{
    gen_poseidon_computing_interaction_trace, gen_poseidon_computing_trace,
    gen_poseidon_scheduler_interaction_trace, gen_poseidon_scheduler_trace,
};

// Poseidon parameters
pub const N_STATE: usize = 16;
pub const RATE: usize = 8; // First 8 elements absorb message
#[allow(dead_code)]
pub const CAPACITY: usize = 8; // Last 8 elements for security
pub const N_PARTIAL_ROUNDS: usize = 14;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const FULL_ROUNDS: usize = 2 * N_HALF_FULL_ROUNDS;
pub const N_COLUMNS: usize = RATE + N_STATE * (1 + FULL_ROUNDS) + N_PARTIAL_ROUNDS + N_STATE;
pub const LOG_EXPAND: u32 = 3; // For constraint degree 6

// TODO(shahars): Use poseidon's real constants.
pub const EXTERNAL_ROUND_CONSTS: [[BaseField; N_STATE]; 2 * N_HALF_FULL_ROUNDS] =
    [[BaseField::from_u32_unchecked(1234); N_STATE]; 2 * N_HALF_FULL_ROUNDS];
pub const INTERNAL_ROUND_CONSTS: [BaseField; N_PARTIAL_ROUNDS] =
    [BaseField::from_u32_unchecked(1234); N_PARTIAL_ROUNDS];

// LogUp relation for 16-element final_state
relation!(PoseidonRelation, N_STATE);

#[inline(always)]
/// Applies the M4 MDS matrix described in <https://eprint.iacr.org/2023/323.pdf> 5.1.
pub fn apply_m4<F>(x: [F; 4]) -> [F; 4]
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    let t0 = x[0].clone() + x[1].clone();
    let t02 = t0.clone() + t0.clone();
    let t1 = x[2].clone() + x[3].clone();
    let t12 = t1.clone() + t1.clone();
    let t2 = x[1].clone() + x[1].clone() + t1.clone();
    let t3 = x[3].clone() + x[3].clone() + t0.clone();
    let t4 = t12.clone() + t12.clone() + t3.clone();
    let t5 = t02.clone() + t02.clone() + t2.clone();
    let t6 = t3.clone() + t5.clone();
    let t7 = t2.clone() + t4.clone();
    [t6, t5, t7, t4]
}

/// Applies the external round matrix.
/// See <https://eprint.iacr.org/2023/323.pdf> 5.1 and Appendix B.
pub fn apply_external_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    // Applies circ(2M4, M4, M4, M4).
    for i in 0..4 {
        [
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ] = apply_m4([
            state[4 * i].clone(),
            state[4 * i + 1].clone(),
            state[4 * i + 2].clone(),
            state[4 * i + 3].clone(),
        ]);
    }
    for j in 0..4 {
        let s =
            state[j].clone() + state[j + 4].clone() + state[j + 8].clone() + state[j + 12].clone();
        for i in 0..4 {
            state[4 * i + j] += s.clone();
        }
    }
}

// Applies the internal round matrix.
//   mu_i = 2^{i+1} + 1.
// See <https://eprint.iacr.org/2023/323.pdf> 5.2.
pub fn apply_internal_round_matrix<F>(state: &mut [F; 16])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    // TODO(shahars): Check that these coefficients are good according to section  5.3 of Poseidon2
    // paper.
    let sum = state[1..]
        .iter()
        .cloned()
        .fold(state[0].clone(), |acc, s| acc + s);
    state.iter_mut().enumerate().for_each(|(i, s)| {
        // TODO(andrew): Change to rotations.
        *s = s.clone() * BaseField::from_u32_unchecked(1 << (i + 1)) + sum.clone();
    });
}

pub fn pow5<F: FieldExpOps>(x: F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x.clone()
}

/// Helper function to compute x^5 for constraint expressions
pub fn pow5_expr<F: Clone + std::ops::Mul<Output = F>>(x: F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x
}

/// Generates the is_first preprocessed column
pub fn gen_is_first_column(
    log_size: u32,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;
    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    col.set(0, BaseField::from_u32_unchecked(1));

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());

    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_first_column_id(log_size: u32) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_first_{}", log_size),
    }
}

/// Generates the is_active preprocessed column
///
/// Marks which rows are "active" (contain real messages) vs "padding" (unused).
/// Active rows have value 1, padding rows have value 0.
///
/// # Arguments
/// * `log_size` - Log2 of trace size
/// * `n_active` - Number of active rows
///
/// # Returns
/// Column where first `n_active` rows are 1, rest are 0 (in sequential order before bit-reversal)
pub fn gen_is_active_column(
    log_size: u32,
    n_active: usize,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;

    assert!(
        n_active <= n_rows,
        "n_active ({}) exceeds n_rows ({}). Use larger log_size.",
        n_active,
        n_rows
    );

    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    // Set first n_active rows to 1
    for i in 0..n_active {
        col.set(i, BaseField::from_u32_unchecked(1));
    }

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());

    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_active_column_id(log_size: u32, n_active: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_active_{}_{}", log_size, n_active),
    }
}

/// Generates the is_target preprocessed column
///
/// Marks which row is the "target" row for LogUp (yields final_state).
/// Only the target row has value 1, all other rows have value 0.
///
/// # Arguments
/// * `log_size` - Log2 of trace size
/// * `n_active` - Number of active rows (target = n_active - 1)
///
/// # Returns
/// Column where only row (n_active - 1) is 1, rest are 0 (in sequential order before bit-reversal)
pub fn gen_is_target_column(
    log_size: u32,
    n_active: usize,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let n_rows = 1 << log_size;

    assert!(
        n_active > 0 && n_active <= n_rows,
        "n_active ({}) must be in range [1, {}]",
        n_active,
        n_rows
    );

    let mut col = Col::<SimdBackend, BaseField>::zeros(n_rows);

    // Set only the target row (last active row) to 1
    let target_row = n_active - 1;
    col.set(target_row, BaseField::from_u32_unchecked(1));

    bit_reverse_coset_to_circle_domain_order(col.as_mut_slice());

    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

pub fn is_target_column_id(log_size: u32, n_active: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("is_target_{}_{}", log_size, n_active),
    }
}

/// Statement 0: Component configuration (log_size)
/// This is mixed into the channel before drawing the PoseidonRelation
#[derive(Clone, Copy, Debug)]
pub struct MultiPoseidonStatement0 {
    pub log_size: u32,
}

impl MultiPoseidonStatement0 {
    pub fn mix_into(&self, channel: &mut Blake2sChannel) {
        channel.mix_u64(self.log_size as u64);
    }

    /// Returns log sizes for all trees (preprocessed, main, interaction)
    pub fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        TreeVec(vec![
            // Tree 0: Preprocessed (5 columns: is_first, is_active_comp1, is_target_comp1,
            // is_active_comp2, is_target_comp2)
            vec![self.log_size; 5],
            // Tree 1: Main traces (N_COLUMNS per computing component + 3*N_STATE for scheduler)
            // Computing1: N_COLUMNS, Computing2: N_COLUMNS, Scheduler: 3*N_STATE
            vec![self.log_size; 2 * N_COLUMNS + 3 * N_STATE],
            // Tree 2: Interaction traces (1 SecureColumn per component = 4 BaseField cols each =
            // 12 cols) 3 components * 4 columns (SECURE_EXTENSION_DEGREE) = 12
            vec![self.log_size; 12],
        ])
    }
}

/// Statement 1: LogUp claimed sums
/// This is mixed into the channel after drawing PoseidonRelation
#[derive(Clone, Copy, Debug)]
pub struct MultiPoseidonStatement1 {
    pub claimed_sum_computing1: SecureField,
    pub claimed_sum_computing2: SecureField,
    pub claimed_sum_scheduler: SecureField,
}

impl MultiPoseidonStatement1 {
    pub fn mix_into(&self, channel: &mut Blake2sChannel) {
        channel.mix_felts(&[
            self.claimed_sum_computing1,
            self.claimed_sum_computing2,
            self.claimed_sum_scheduler,
        ]);
    }
}

/// Prove multi-component Poseidon with LogUp
///
/// This generates a STARK proof for:
/// - Computing1: Poseidon hash for n_messages_comp1
/// - Computing2: Poseidon hash for n_messages_comp2
/// - Scheduler: Uses final_states from both and computes element-wise sum
///
/// LogUp verifies that Scheduler uses the correct values from both Computing components.
pub fn prove_multi_poseidon(
    n_messages_comp1: usize,
    messages_comp1: Vec<[BaseField; RATE]>,
    n_messages_comp2: usize,
    messages_comp2: Vec<[BaseField; RATE]>,
    channel: &mut Blake2sChannel,
    mut commitment_scheme: CommitmentSchemeProver<SimdBackend, Blake2sMerkleChannel>,
) -> Result<
    (
        StarkProof<Blake2sMerkleHasher>,
        [PoseidonComputingComponent; 2],
        PoseidonSchedulerComponent,
        MultiPoseidonStatement0,
        MultiPoseidonStatement1,
    ),
    Box<dyn std::error::Error>,
> {
    // Step 0: Compute dynamic log_size
    let max_messages = n_messages_comp1.max(n_messages_comp2);
    let min_rows = max_messages;
    let min_log_size = if min_rows <= 1 {
        0
    } else {
        (min_rows - 1).ilog2() + 1 // log2_ceil
    };
    let log_size = min_log_size.max(4); // minimum 16 rows for SIMD (LOG_N_LANES = 4)

    println!("=== Multi-Component Poseidon Proof Generation ===");
    println!(
        "Messages: Computing1={}, Computing2={}",
        n_messages_comp1, n_messages_comp2
    );
    println!("Computed log_size: {} ({} rows)\n", log_size, 1 << log_size);

    // Step 1: Generate and commit preprocessed columns
    println!("Step 1: Generating and committing preprocessed columns...");
    let is_first_col = gen_is_first_column(log_size);
    let is_active_comp1_col = gen_is_active_column(log_size, n_messages_comp1);
    let is_target_comp1_col = gen_is_target_column(log_size, n_messages_comp1);
    let is_active_comp2_col = gen_is_active_column(log_size, n_messages_comp2);
    let is_target_comp2_col = gen_is_target_column(log_size, n_messages_comp2);

    let preprocessed_trace = vec![
        is_first_col,
        is_active_comp1_col,
        is_target_comp1_col,
        is_active_comp2_col,
        is_target_comp2_col,
    ];
    println!("Generated 5 preprocessed columns");

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preprocessed_trace);
    tree_builder.commit(channel);

    // Mix Statement0 (log_size) into channel
    let statement0 = MultiPoseidonStatement0 { log_size };
    statement0.mix_into(channel);

    // Step 2: Generate main traces for all components
    println!("\nStep 2: Generating main traces...");
    let (trace_computing1, final_state1) =
        gen_poseidon_computing_trace(log_size, n_messages_comp1, messages_comp1);
    let (trace_computing2, final_state2) =
        gen_poseidon_computing_trace(log_size, n_messages_comp2, messages_comp2);
    let trace_scheduler = gen_poseidon_scheduler_trace(log_size, final_state1, final_state2);
    println!(
        "Computing1 trace: {} rows, {} active messages",
        1 << log_size,
        n_messages_comp1
    );
    println!(
        "Computing2 trace: {} rows, {} active messages",
        1 << log_size,
        n_messages_comp2
    );
    println!("Scheduler trace: {} rows", 1 << log_size);

    // Step 3: Commit main traces
    println!("\nStep 3: Committing main traces...");
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        [
            trace_computing1.clone(),
            trace_computing2.clone(),
            trace_scheduler.clone(),
        ]
        .concat(),
    );
    tree_builder.commit(channel);

    // Step 4: Draw PoseidonRelation from channel
    println!("\nStep 4: Drawing LogUp relation from channel...");
    let poseidon_relation = PoseidonRelation::draw(channel);

    // Step 5: Generate interaction traces (LogUp columns)
    println!("\nStep 5: Generating LogUp interaction traces...");
    let (interaction_trace_computing1, claimed_sum_computing1) =
        gen_poseidon_computing_interaction_trace(
            &trace_computing1,
            &poseidon_relation,
            n_messages_comp1,
        );

    let (interaction_trace_computing2, claimed_sum_computing2) =
        gen_poseidon_computing_interaction_trace(
            &trace_computing2,
            &poseidon_relation,
            n_messages_comp2,
        );

    let (interaction_trace_scheduler, claimed_sum_scheduler) =
        gen_poseidon_scheduler_interaction_trace(&trace_scheduler, &poseidon_relation);

    // Step 6: Verify LogUp property: sum of all claimed_sums should be 0
    let total_sum = claimed_sum_computing1 + claimed_sum_computing2 + claimed_sum_scheduler;
    println!("\nLogUp verification:");
    println!("  Computing1 yields: {:?}", claimed_sum_computing1);
    println!("  Computing2 yields: {:?}", claimed_sum_computing2);
    println!("  Scheduler uses:    {:?}", claimed_sum_scheduler);
    println!("  Total sum:         {:?}", total_sum);
    if total_sum == Zero::zero() {
        println!("✅ LogUp property satisfied: total sum = 0");
    } else {
        println!("⚠️  Warning: LogUp sum is not zero!");
    }

    // Mix Statement1 (claimed_sums) into channel
    let statement1 = MultiPoseidonStatement1 {
        claimed_sum_computing1,
        claimed_sum_computing2,
        claimed_sum_scheduler,
    };
    statement1.mix_into(channel);

    // Step 7: Commit interaction traces
    println!("\nStep 6: Committing interaction traces...");
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        [
            interaction_trace_computing1,
            interaction_trace_computing2,
            interaction_trace_scheduler,
        ]
        .concat(),
    );
    tree_builder.commit(channel);

    // Step 8: Create components with TraceLocationAllocator
    println!("\nStep 7: Creating components...");
    let mut tree_span_provider = TraceLocationAllocator::default();
    let is_first_id = is_first_column_id(log_size);

    let component_computing1 = PoseidonComputingComponent::new(
        &mut tree_span_provider,
        PoseidonComputingEval {
            log_n_rows: log_size,
            n_active_messages: n_messages_comp1,
            poseidon_relation: poseidon_relation.clone(),
            claimed_sum: claimed_sum_computing1,
            is_first_id: is_first_id.clone(),
            is_active_id: is_active_column_id(log_size, n_messages_comp1),
            is_target_id: is_target_column_id(log_size, n_messages_comp1),
        },
        claimed_sum_computing1,
    );

    let component_computing2 = PoseidonComputingComponent::new(
        &mut tree_span_provider,
        PoseidonComputingEval {
            log_n_rows: log_size,
            n_active_messages: n_messages_comp2,
            poseidon_relation: poseidon_relation.clone(),
            claimed_sum: claimed_sum_computing2,
            is_first_id: is_first_id.clone(),
            is_active_id: is_active_column_id(log_size, n_messages_comp2),
            is_target_id: is_target_column_id(log_size, n_messages_comp2),
        },
        claimed_sum_computing2,
    );

    let component_scheduler = PoseidonSchedulerComponent::new(
        &mut tree_span_provider,
        PoseidonSchedulerEval {
            log_n_rows: log_size,
            poseidon_relation,
            claimed_sum: claimed_sum_scheduler,
            is_first_id: is_first_id.clone(),
        },
        claimed_sum_scheduler,
    );

    // Step 9: Generate proof
    println!("\nStep 8: Generating STARK proof...");
    let proof = prove(
        &[
            &component_computing1,
            &component_computing2,
            &component_scheduler,
        ],
        channel,
        commitment_scheme,
    )?;
    println!("✅ Proof generated successfully!");

    Ok((
        proof,
        [component_computing1, component_computing2],
        component_scheduler,
        statement0,
        statement1,
    ))
}

/// Verify multi-component Poseidon proof with LogUp
///
/// This verifies a STARK proof for the multi-component Poseidon circuit.
/// The verifier must commit to the same tree structure as the prover.
pub fn verify_multi_poseidon(
    proof: StarkProof<Blake2sMerkleHasher>,
    n_messages_comp1: usize,
    n_messages_comp2: usize,
    statement0: MultiPoseidonStatement0,
    statement1: MultiPoseidonStatement1,
    config: stwo::core::pcs::PcsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use stwo::core::pcs::CommitmentSchemeVerifier;

    println!("\n=== Multi-Component Poseidon Proof Verification ===");
    println!(
        "Messages: Computing1={}, Computing2={}\n",
        n_messages_comp1, n_messages_comp2
    );

    // Extract log_size from statement
    let log_size = statement0.log_size;

    // Step 1: Setup verifier channel and commitment scheme
    println!("Step 1: Setting up verifier...");
    let channel = &mut Blake2sChannel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);
    let log_sizes = statement0.log_sizes();

    // Step 2: Commit preprocessed columns
    println!("\nStep 2: Committing preprocessed columns...");
    commitment_scheme.commit(proof.commitments[0], &log_sizes[0], channel);

    // Mix Statement0 (log_size) into channel
    statement0.mix_into(channel);

    // Step 3: Commit main traces
    println!("\nStep 3: Committing main traces...");
    commitment_scheme.commit(proof.commitments[1], &log_sizes[1], channel);

    // Step 4: Draw PoseidonRelation from channel (must match prover)
    println!("\nStep 4: Drawing LogUp relation from channel...");
    let poseidon_relation = PoseidonRelation::draw(channel);

    // Mix Statement1 (claimed_sums) into channel
    statement1.mix_into(channel);

    // Step 5: Commit interaction traces
    println!("\nStep 5: Committing interaction traces...");
    commitment_scheme.commit(proof.commitments[2], &log_sizes[2], channel);

    // Step 6: Create components (AFTER committing interaction traces, matching prover order)
    println!("\nStep 6: Creating components for verification...");
    let mut tree_span_provider = TraceLocationAllocator::default();
    let is_first_id = is_first_column_id(log_size);

    let component_computing1 = PoseidonComputingComponent::new(
        &mut tree_span_provider,
        PoseidonComputingEval {
            log_n_rows: log_size,
            n_active_messages: n_messages_comp1,
            poseidon_relation: poseidon_relation.clone(),
            claimed_sum: statement1.claimed_sum_computing1,
            is_first_id: is_first_id.clone(),
            is_active_id: is_active_column_id(log_size, n_messages_comp1),
            is_target_id: is_target_column_id(log_size, n_messages_comp1),
        },
        statement1.claimed_sum_computing1,
    );

    let component_computing2 = PoseidonComputingComponent::new(
        &mut tree_span_provider,
        PoseidonComputingEval {
            log_n_rows: log_size,
            n_active_messages: n_messages_comp2,
            poseidon_relation: poseidon_relation.clone(),
            claimed_sum: statement1.claimed_sum_computing2,
            is_first_id: is_first_id.clone(),
            is_active_id: is_active_column_id(log_size, n_messages_comp2),
            is_target_id: is_target_column_id(log_size, n_messages_comp2),
        },
        statement1.claimed_sum_computing2,
    );

    let component_scheduler = PoseidonSchedulerComponent::new(
        &mut tree_span_provider,
        PoseidonSchedulerEval {
            log_n_rows: log_size,
            poseidon_relation,
            claimed_sum: statement1.claimed_sum_scheduler,
            is_first_id: is_first_id.clone(),
        },
        statement1.claimed_sum_scheduler,
    );

    // Step 7: Verify the proof
    println!("\nStep 7: Verifying STARK proof...");
    stwo::core::verifier::verify(
        &[
            &component_computing1,
            &component_computing2,
            &component_scheduler,
        ],
        channel,
        commitment_scheme,
        proof,
    )?;
    println!("✅ Proof verified successfully!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use stwo::core::channel::Blake2sChannel;
    use stwo::core::pcs::PcsConfig;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::poly::circle::PolyOps;
    use stwo::prover::CommitmentSchemeProver;

    use super::*;

    #[test]
    fn test_multi_component_poseidon_proof() {
        println!("\n==================================================");
        println!("  MULTI-COMPONENT POSEIDON PROOF TEST");
        println!("==================================================\n");

        let n_messages_comp1 = 3;
        let n_messages_comp2 = 5;

        // Create some test messages
        let messages_comp1: Vec<[BaseField; RATE]> = (0..n_messages_comp1)
            .map(|i| std::array::from_fn(|j| BaseField::from_u32_unchecked((i * RATE + j) as u32)))
            .collect();

        let messages_comp2: Vec<[BaseField; RATE]> = (0..n_messages_comp2)
            .map(|i| {
                std::array::from_fn(|j| BaseField::from_u32_unchecked((i * RATE + j + 100) as u32))
            })
            .collect();

        // Setup prover
        let config = PcsConfig::default();

        // Compute expected log_size for twiddles
        let max_messages = n_messages_comp1.max(n_messages_comp2) as u32;
        let min_log_size = if max_messages <= 1 {
            0
        } else {
            (max_messages - 1).ilog2() + 1
        };
        let log_size = min_log_size.max(4);

        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(log_size + LOG_EXPAND + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );

        let channel = &mut Blake2sChannel::default();
        let commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        // Generate proof
        let result = prove_multi_poseidon(
            n_messages_comp1,
            messages_comp1,
            n_messages_comp2,
            messages_comp2,
            channel,
            commitment_scheme,
        );

        match result {
            Ok((proof, _components, _scheduler, _statement0, _statement1)) => {
                println!("\n==================================================");
                println!("  PROOF GENERATION SUCCESSFUL!");
                println!("==================================================\n");

                println!("Proof details:");
                println!("  - Number of commitments: {}", proof.commitments.len());
                println!("  - Computing components: 2");
                println!("  - Scheduler component: 1");

                println!("\n✅ Multi-component Poseidon proof generated successfully!");
            }
            Err(e) => {
                panic!("Proof generation failed: {:?}", e);
            }
        }
    }

    #[test]
    fn test_prove_and_verify() {
        println!("\n==================================================");
        println!("  MULTI-COMPONENT POSEIDON: PROVE + VERIFY");
        println!("==================================================\n");

        let n_messages_comp1 = 3;
        let n_messages_comp2 = 5;

        // Create some test messages
        let messages_comp1: Vec<[BaseField; RATE]> = (0..n_messages_comp1)
            .map(|i| std::array::from_fn(|j| BaseField::from_u32_unchecked((i * RATE + j) as u32)))
            .collect();

        let messages_comp2: Vec<[BaseField; RATE]> = (0..n_messages_comp2)
            .map(|i| {
                std::array::from_fn(|j| BaseField::from_u32_unchecked((i * RATE + j + 100) as u32))
            })
            .collect();

        // Setup prover
        let config = PcsConfig::default();

        // Compute expected log_size for twiddles
        let max_messages = n_messages_comp1.max(n_messages_comp2) as u32;
        let min_log_size = if max_messages <= 1 {
            0
        } else {
            (max_messages - 1).ilog2() + 1
        };
        let log_size = min_log_size.max(4);

        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(log_size + LOG_EXPAND + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );

        let channel = &mut Blake2sChannel::default();
        let commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        // STEP 1: Generate proof
        println!("==================================================");
        println!("STEP 1: PROVING");
        println!("==================================================");

        let result = prove_multi_poseidon(
            n_messages_comp1,
            messages_comp1,
            n_messages_comp2,
            messages_comp2,
            channel,
            commitment_scheme,
        );

        match result {
            Ok((proof, _components, _scheduler, statement0, statement1)) => {
                println!("\n✅ Proof generated successfully!");
                println!("  - Commitments: {}", proof.commitments.len());

                // STEP 2: Verify proof
                println!("\n==================================================");
                println!("STEP 2: VERIFYING");
                println!("==================================================");

                let verify_result = verify_multi_poseidon(
                    proof,
                    n_messages_comp1,
                    n_messages_comp2,
                    statement0,
                    statement1,
                    config,
                );

                match verify_result {
                    Ok(()) => {
                        println!("\n==================================================");
                        println!("  ✅✅✅ SUCCESS! ✅✅✅");
                        println!("==================================================");
                        println!("\nProof was generated AND verified successfully!");
                        println!("\nThis proves:");
                        println!(
                            "  1. Computing1 correctly hashed {} messages",
                            n_messages_comp1
                        );
                        println!(
                            "  2. Computing2 correctly hashed {} messages",
                            n_messages_comp2
                        );
                        println!("  3. Scheduler correctly summed both final_states");
                        println!("  4. LogUp verified that Scheduler used correct values");
                        println!("  5. Verifier independently confirmed all constraints!");
                    }
                    Err(e) => {
                        panic!("Verification failed: {:?}", e);
                    }
                }
            }
            Err(e) => {
                panic!("Proof generation failed: {:?}", e);
            }
        }
    }

    #[test]
    fn test_different_log_sizes_experiment() {
        println!("\n==================================================");
        println!("  EXPERIMENT: DIFFERENT LOG_SIZES PER COMPONENT");
        println!("==================================================\n");

        let n_messages_comp1 = 3;   // Needs log_size = 2 (4 rows min) or 4 (16 rows for SIMD)
        let n_messages_comp2 = 50;  // Needs log_size = 6 (64 rows)

        println!("Computing1: {} messages → log_size = 4 (16 rows)", n_messages_comp1);
        println!("Computing2: {} messages → log_size = 6 (64 rows)", n_messages_comp2);
        println!("\nTrying to use DIFFERENT log_sizes...\n");

        // Create test messages
        let messages_comp1: Vec<[BaseField; RATE]> = (0..n_messages_comp1)
            .map(|i| std::array::from_fn(|j| BaseField::from_u32_unchecked((i * RATE + j) as u32)))
            .collect();

        let messages_comp2: Vec<[BaseField; RATE]> = (0..n_messages_comp2)
            .map(|i| std::array::from_fn(|j| BaseField::from_u32_unchecked((i * RATE + j + 100) as u32)))
            .collect();

        let config = PcsConfig::default();

        // EXPERIMENT: Try different log_sizes
        let log_size_comp1 = 4;  // 16 rows for Computing1
        let log_size_comp2 = 6;  // 64 rows for Computing2
        let log_size_scheduler = log_size_comp2.max(log_size_comp1);  // Use max for scheduler

        println!("Generating traces with DIFFERENT log_sizes:");
        println!("  - Computing1 trace: log_size = {} ({} rows)", log_size_comp1, 1 << log_size_comp1);
        println!("  - Computing2 trace: log_size = {} ({} rows)", log_size_comp2, 1 << log_size_comp2);
        println!("  - Scheduler trace: log_size = {} ({} rows)", log_size_scheduler, 1 << log_size_scheduler);

        // Generate traces with DIFFERENT log_sizes
        let (trace_computing1, final_state1) = gen_poseidon_computing_trace(log_size_comp1, n_messages_comp1, messages_comp1);
        let (trace_computing2, final_state2) = gen_poseidon_computing_trace(log_size_comp2, n_messages_comp2, messages_comp2);
        let trace_scheduler = gen_poseidon_scheduler_trace(log_size_scheduler, final_state1, final_state2);

        println!("\n✅ Traces generated successfully with different sizes!");
        println!("  - Computing1: {} columns x {} rows", trace_computing1.len(), 1 << log_size_comp1);
        println!("  - Computing2: {} columns x {} rows", trace_computing2.len(), 1 << log_size_comp2);
        println!("  - Scheduler: {} columns x {} rows", trace_scheduler.len(), 1 << log_size_scheduler);

        // Now try to commit them to Merkle tree
        println!("\nNow trying to commit to Merkle tree...");

        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(log_size_scheduler + LOG_EXPAND + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );

        let channel = &mut Blake2sChannel::default();
        let mut commitment_scheme = CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(
            config,
            &twiddles,
        );

        let mut tree_builder = commitment_scheme.tree_builder();

        println!("Attempting to extend_evals with DIFFERENT sized traces...");
        // This will likely FAIL because all columns in a tree must have same size!
        tree_builder.extend_evals([trace_computing1, trace_computing2, trace_scheduler].concat());

        println!("✅ extend_evals succeeded!");

        // Try to commit
        println!("Attempting to commit...");
        tree_builder.commit(channel);

        println!("✅✅✅ COMMIT SUCCEEDED! Different log_sizes work!");
    }
}
