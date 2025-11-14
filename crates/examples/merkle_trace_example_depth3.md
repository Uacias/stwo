# Merkle Path Verification - Complete Example (Depth=3)

## Setup

**Tree Structure:** 8 leaves (2^3), depth=3
**Proving:** L5 (index=5, binary: `101`) belongs to the tree

```
                ROOT
             /        \
          H03          H47
         /   \        /   \
       H01   H23    H45   H67
      / \   / \    / \   / \
     L0 L1 L2 L3  L4 L5 L6 L7
                      ↑
                  index=5
```

**Path to verify:**
- L5 → H45 → H47 → ROOT

**Siblings needed:**
- Level 0: L4 (sibling of L5)
- Level 1: H67 (sibling of H45)
- Level 2: H03 (sibling of H47)

**Index bits (5 = 101 binary):**
- Bit 0 (LSB): 1 → L5 is on RIGHT, L4 on LEFT
- Bit 1: 0 → H45 is on LEFT, H67 on RIGHT
- Bit 2 (MSB): 1 → H47 is on RIGHT, H03 on LEFT

**Total trace rows:** 2 × depth = **6 rows**

---

## Row-by-Row Execution

### ROW 0: Level 0, First Absorption

**Calculation:**
```rust
level = row / 2 = 0 / 2 = 0
is_second_absorption = (row % 2 == 1) = (0 % 2 == 1) = false
is_level_start = !is_second_absorption = true
index_bit = (index >> level) & 1 = (5 >> 0) & 1 = 5 & 1 = 1
```

**Message determination:**
```rust
if !is_second_absorption {  // true
    if index_bit == 0 {     // false (index_bit = 1)
        current_node
    } else {
        siblings[level]     // ← This executes!
    }
}

message = siblings[0] = L4
```

**Initial state construction:**
```rust
// row == 0 → First row special case
state = [message, zeros]
     = [L4, L4, L4, L4, L4, L4, L4, L4,  0, 0, 0, 0, 0, 0, 0, 0]
        ↑──────────rate (8)────────────↑  ↑────capacity (8)────↑
```

**Trace columns written:**
```
message[0..8]:        [L4, L4, L4, L4, L4, L4, L4, L4]
initial_state[0..16]: [L4, L4, L4, L4, L4, L4, L4, L4, 0, 0, 0, 0, 0, 0, 0, 0]
```

**Poseidon computation:**
```
state = Poseidon(initial_state)
     = [X0, X1, X2, X3, X4, X5, X6, X7, C0, C1, C2, C3, C4, C5, C6, C7]
       ↑────────rate──────────────────↑  ↑────────capacity────────────↑
```

**Trace columns written:**
```
intermediate states... (from Poseidon rounds)
final_state[0..16]: [X0, X1, X2, X3, X4, X5, X6, X7, C0, C1, C2, C3, C4, C5, C6, C7]
```

**State updates:**
```rust
prev_output = state  // Save all 16 elements for next row
// current_node NOT updated (only after odd rows)
```

---

### ROW 1: Level 0, Second Absorption

**Calculation:**
```rust
level = row / 2 = 1 / 2 = 0
is_second_absorption = (row % 2 == 1) = (1 % 2 == 1) = true
is_level_start = !is_second_absorption = false
index_bit = (index >> level) & 1 = (5 >> 0) & 1 = 1
```

**Message determination:**
```rust
if !is_second_absorption {  // false
    ...
} else {                    // ← This branch
    if index_bit == 0 {     // false (index_bit = 1)
        siblings[level]
    } else {
        current_node        // ← This executes!
    }
}

message = current_node = L5  // (the leaf we're proving)
```

**Initial state construction:**
```rust
// is_level_start = false → CHAINING enabled!
state = [prev_output[0..8] + message, prev_output[8..16]]
     = [X0+L5, X1+L5, X2+L5, X3+L5, X4+L5, X5+L5, X6+L5, X7+L5,
        C0, C1, C2, C3, C4, C5, C6, C7]
       ↑──────────rate (absorb message)──────────────────────↑
                                        ↑──capacity (preserved)──↑
```

**Trace columns written:**
```
message[0..8]:        [L5, L5, L5, L5, L5, L5, L5, L5]
initial_state[0..16]: [X0+L5, X1+L5, ..., X7+L5, C0, C1, ..., C7]
```

**Poseidon computation:**
```
state = Poseidon(initial_state)
     = [H45_0, H45_1, H45_2, H45_3, H45_4, H45_5, H45_6, H45_7,
        Cap0, Cap1, Cap2, Cap3, Cap4, Cap5, Cap6, Cap7]
       ↑────────H45 (hash of L4+L5)───────────────────────────↑
```

**Trace columns written:**
```
intermediate states... (from Poseidon rounds)
final_state[0..16]: [H45_0, ..., H45_7, Cap0, ..., Cap7]
```

**State updates:**
```rust
prev_output = state  // Save all 16 elements

// is_second_absorption = true → Update current_node!
current_node.copy_from_slice(&state[0..RATE])
current_node = [H45_0, H45_1, H45_2, H45_3, H45_4, H45_5, H45_6, H45_7]
               ↑────────Only rate part (8 elements)───────────────────↑
```

**✓ Level 0 complete: Hash(L4, L5) = H45**

---

### ROW 2: Level 1, First Absorption

**Calculation:**
```rust
level = row / 2 = 2 / 2 = 1
is_second_absorption = (row % 2 == 1) = (2 % 2 == 1) = false
is_level_start = !is_second_absorption = true  ← NEW LEVEL!
index_bit = (index >> level) & 1 = (5 >> 1) & 1 = 2 & 1 = 0
```

**Message determination:**
```rust
if !is_second_absorption {  // true
    if index_bit == 0 {     // true (index_bit = 0)
        current_node        // ← This executes!
    } else {
        siblings[level]
    }
}

message = current_node = H45  // (computed from previous level)
        = [H45_0, H45_1, H45_2, H45_3, H45_4, H45_5, H45_6, H45_7]
```

**Initial state construction:**
```rust
// is_level_start = true → CAPACITY RESET!
state = [message, zeros]
     = [H45_0, H45_1, H45_2, H45_3, H45_4, H45_5, H45_6, H45_7,
        0, 0, 0, 0, 0, 0, 0, 0]
       ↑──────────rate──────────────────────────────────────↑
                                ↑────capacity RESET to 0────↑
```

**Trace columns written:**
```
message[0..8]:        [H45_0, H45_1, H45_2, H45_3, H45_4, H45_5, H45_6, H45_7]
initial_state[0..16]: [H45_0, ..., H45_7, 0, 0, 0, 0, 0, 0, 0, 0]
```

**Poseidon computation:**
```
state = Poseidon(initial_state)
     = [Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, D0, D1, D2, D3, D4, D5, D6, D7]
```

**Trace columns written:**
```
intermediate states... (from Poseidon rounds)
final_state[0..16]: [Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, D0, D1, D2, D3, D4, D5, D6, D7]
```

**State updates:**
```rust
prev_output = state  // Save all 16 elements for next row
// current_node NOT updated (only after odd rows)
```

---

### ROW 3: Level 1, Second Absorption

**Calculation:**
```rust
level = row / 2 = 3 / 2 = 1
is_second_absorption = (row % 2 == 1) = (3 % 2 == 1) = true
is_level_start = !is_second_absorption = false
index_bit = (index >> level) & 1 = (5 >> 1) & 1 = 0
```

**Message determination:**
```rust
if !is_second_absorption {  // false
    ...
} else {                    // ← This branch
    if index_bit == 0 {     // true (index_bit = 0)
        siblings[level]     // ← This executes!
    } else {
        current_node
    }
}

message = siblings[1] = H67
```

**Initial state construction:**
```rust
// is_level_start = false → CHAINING enabled!
state = [prev_output[0..8] + message, prev_output[8..16]]
     = [Y0+H67_0, Y1+H67_1, Y2+H67_2, Y3+H67_3, Y4+H67_4, Y5+H67_5, Y6+H67_6, Y7+H67_7,
        D0, D1, D2, D3, D4, D5, D6, D7]
       ↑──────────rate (absorb message)──────────────────────────────────────────────↑
                                              ↑──────capacity (preserved from row 2)──↑
```

**Trace columns written:**
```
message[0..8]:        [H67_0, H67_1, H67_2, H67_3, H67_4, H67_5, H67_6, H67_7]
initial_state[0..16]: [Y0+H67_0, Y1+H67_1, ..., Y7+H67_7, D0, D1, ..., D7]
```

**Poseidon computation:**
```
state = Poseidon(initial_state)
     = [H47_0, H47_1, H47_2, H47_3, H47_4, H47_5, H47_6, H47_7,
        Cap0, Cap1, Cap2, Cap3, Cap4, Cap5, Cap6, Cap7]
       ↑────────H47 (hash of H45+H67)────────────────────────↑
```

**Trace columns written:**
```
intermediate states... (from Poseidon rounds)
final_state[0..16]: [H47_0, ..., H47_7, Cap0, ..., Cap7]
```

**State updates:**
```rust
prev_output = state  // Save all 16 elements

// is_second_absorption = true → Update current_node!
current_node.copy_from_slice(&state[0..RATE])
current_node = [H47_0, H47_1, H47_2, H47_3, H47_4, H47_5, H47_6, H47_7]
               ↑────────Only rate part (8 elements)───────────────────↑
```

**✓ Level 1 complete: Hash(H45, H67) = H47**

---

### ROW 4: Level 2, First Absorption

**Calculation:**
```rust
level = row / 2 = 4 / 2 = 2
is_second_absorption = (row % 2 == 1) = (4 % 2 == 1) = false
is_level_start = !is_second_absorption = true  ← NEW LEVEL!
index_bit = (index >> level) & 1 = (5 >> 2) & 1 = 1 & 1 = 1
```

**Message determination:**
```rust
if !is_second_absorption {  // true
    if index_bit == 0 {     // false (index_bit = 1)
        current_node
    } else {
        siblings[level]     // ← This executes!
    }
}

message = siblings[2] = H03
```

**Initial state construction:**
```rust
// is_level_start = true → CAPACITY RESET!
state = [message, zeros]
     = [H03_0, H03_1, H03_2, H03_3, H03_4, H03_5, H03_6, H03_7,
        0, 0, 0, 0, 0, 0, 0, 0]
       ↑──────────rate──────────────────────────────────────↑
                                ↑────capacity RESET to 0────↑
```

**Trace columns written:**
```
message[0..8]:        [H03_0, H03_1, H03_2, H03_3, H03_4, H03_5, H03_6, H03_7]
initial_state[0..16]: [H03_0, ..., H03_7, 0, 0, 0, 0, 0, 0, 0, 0]
```

**Poseidon computation:**
```
state = Poseidon(initial_state)
     = [Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, E0, E1, E2, E3, E4, E5, E6, E7]
```

**Trace columns written:**
```
intermediate states... (from Poseidon rounds)
final_state[0..16]: [Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, E0, E1, E2, E3, E4, E5, E6, E7]
```

**State updates:**
```rust
prev_output = state  // Save all 16 elements for next row
// current_node NOT updated (only after odd rows)
```

---

### ROW 5: Level 2, Second Absorption (FINAL ROW!)

**Calculation:**
```rust
level = row / 2 = 5 / 2 = 2
is_second_absorption = (row % 2 == 1) = (5 % 2 == 1) = true
is_level_start = !is_second_absorption = false
index_bit = (index >> level) & 1 = (5 >> 2) & 1 = 1
```

**Message determination:**
```rust
if !is_second_absorption {  // false
    ...
} else {                    // ← This branch
    if index_bit == 0 {     // false (index_bit = 1)
        siblings[level]
    } else {
        current_node        // ← This executes!
    }
}

message = current_node = H47  // (computed from previous level)
        = [H47_0, H47_1, H47_2, H47_3, H47_4, H47_5, H47_6, H47_7]
```

**Initial state construction:**
```rust
// is_level_start = false → CHAINING enabled!
state = [prev_output[0..8] + message, prev_output[8..16]]
     = [Z0+H47_0, Z1+H47_1, Z2+H47_2, Z3+H47_3, Z4+H47_4, Z5+H47_5, Z6+H47_6, Z7+H47_7,
        E0, E1, E2, E3, E4, E5, E6, E7]
       ↑──────────rate (absorb message)──────────────────────────────────────────────↑
                                              ↑──────capacity (preserved from row 4)──↑
```

**Trace columns written:**
```
message[0..8]:        [H47_0, H47_1, H47_2, H47_3, H47_4, H47_5, H47_6, H47_7]
initial_state[0..16]: [Z0+H47_0, Z1+H47_1, ..., Z7+H47_7, E0, E1, ..., E7]
```

**Poseidon computation:**
```
state = Poseidon(initial_state)
     = [ROOT_0, ROOT_1, ROOT_2, ROOT_3, ROOT_4, ROOT_5, ROOT_6, ROOT_7,
        Cap0, Cap1, Cap2, Cap3, Cap4, Cap5, Cap6, Cap7]
       ↑────────ROOT (final Merkle root)──────────────────────────────↑
```

**Trace columns written:**
```
intermediate states... (from Poseidon rounds)
final_state[0..16]: [ROOT_0, ..., ROOT_7, Cap0, ..., Cap7]
```

**State updates:**
```rust
prev_output = state  // Save all 16 elements

// is_second_absorption = true → Update current_node!
current_node.copy_from_slice(&state[0..RATE])
current_node = [ROOT_0, ROOT_1, ROOT_2, ROOT_3, ROOT_4, ROOT_5, ROOT_6, ROOT_7]

// row == n_active_rows - 1 (5 == 6 - 1) → Save computed_root!
computed_root.copy_from_slice(&state[0..RATE])
computed_root = [ROOT_0, ROOT_1, ROOT_2, ROOT_3, ROOT_4, ROOT_5, ROOT_6, ROOT_7]
```

**✓ Level 2 complete: Hash(H03, H47) = ROOT**

---

## Summary

### Computation Flow

```
Level 0 (rows 0-1):
  Row 0: Absorb L4         (first, capacity=0)
  Row 1: Absorb L5         (second, chaining)
  → Output: H45 = Hash(L4, L5)

Level 1 (rows 2-3):
  Row 2: Absorb H45        (first, capacity=0 RESET)
  Row 3: Absorb H67        (second, chaining)
  → Output: H47 = Hash(H45, H67)

Level 2 (rows 4-5):
  Row 4: Absorb H03        (first, capacity=0 RESET)
  Row 5: Absorb H47        (second, chaining)
  → Output: ROOT = Hash(H03, H47)
```

### Key Observations

1. **Each level = exactly 2 rows (2 absorptions)**
   - Even rows (0, 2, 4): First absorption, capacity RESET to 0
   - Odd rows (1, 3, 5): Second absorption, capacity PRESERVED

2. **Capacity reset pattern:**
   - Row 0: capacity = 0 (fresh sponge)
   - Row 1: capacity = preserved from row 0
   - Row 2: capacity = 0 (NEW LEVEL - fresh sponge)
   - Row 3: capacity = preserved from row 2
   - Row 4: capacity = 0 (NEW LEVEL - fresh sponge)
   - Row 5: capacity = preserved from row 4

3. **Message absorption order determined by index bits:**
   - Index = 5 = binary `101`
   - Bit 0 = 1: L4 first, L5 second
   - Bit 1 = 0: H45 first, H67 second
   - Bit 2 = 1: H03 first, H47 second

4. **current_node updates:**
   - After row 1: current_node = H45 (rate only, 8 elements)
   - After row 3: current_node = H47 (rate only, 8 elements)
   - After row 5: current_node = ROOT (rate only, 8 elements)

5. **Final output:**
   - computed_root = final_state[0..8] from row 5
   - Contains only rate part (8 elements)
   - Yielded to LogUp with multiplicity +1

### Trace Structure

Each row has these columns:
- `message[0..8]`: 8 elements to absorb
- `initial_state[0..16]`: 16 elements (8 rate + 8 capacity)
- `intermediate_full1[0..64]`: 4 full rounds × 16 elements
- `intermediate_partial[0..14]`: 14 partial rounds × 1 element
- `intermediate_full2[0..64]`: 4 full rounds × 16 elements
- `final_state[0..16]`: 16 elements output

Total columns per row: 8 + 16 + 64 + 14 + 64 + 16 = **182 columns**

### LogUp Interaction

- **Computing component** (last row only):
  - Yields: `+1 / combine(computed_root)`
  - Row 5: multiplicity = +1
  - All other rows: multiplicity = 0

- **Scheduler component** (first row only):
  - Uses: `-1 / combine(computed_root)`
  - Row 0: multiplicity = -1
  - All other rows: multiplicity = 0

- **Total sum:** +1 - 1 = 0 ✓
  - This ensures computed_root from Computing equals the value used by Scheduler
