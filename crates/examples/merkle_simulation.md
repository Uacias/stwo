# 🌳 Merkle Tree Proof - Pełna Symulacja

## Przykład: Drzewo głębokości 2 (4 liście)

### KROK 1: Budowanie Drzewa

```
Struktura:
                        ROOT
                       /    \
                     /        \
                  H01          H23
                 /   \        /   \
               L0    L1     L2    L3
```

#### Liście (RATE=8 elementów M31):
```
L0 = [10, 0, 0, 0, 0, 0, 0, 0]
L1 = [20, 0, 0, 0, 0, 0, 0, 0]
L2 = [30, 0, 0, 0, 0, 0, 0, 0]  ← CHCEMY UDOWODNIĆ TEN
L3 = [40, 0, 0, 0, 0, 0, 0, 0]
```

#### Hashowanie poziomu 0 → 1:

**Hash(L0, L1) → H01:**
```
SPONGE CONSTRUCTION (2 absorpcje):

Absorpcja 1 (L0):
  state = [10,0,0,0,0,0,0,0, | 0,0,0,0,0,0,0,0]
           └─────RATE─────┘   └────CAPACITY───┘

  Poseidon(state) → output1

Absorpcja 2 (L1):
  state = [output1[0]+20, output1[1], ..., output1[7] | output1[8], ..., output1[15]]
           └─────add L1 to rate──────────────────┘   └────preserve capacity────────┘

  Poseidon(state) → output2

  H01 = output2[0..8] (RATE part)
```

**Hash(L2, L3) → H23:**
```
Similar sponge construction with L2, L3
→ H23 = [hash values...]
```

#### Hashowanie poziomu 1 → root:

**Hash(H01, H23) → ROOT:**
```
Absorpcja 1 (H01) + Absorpcja 2 (H23)
→ ROOT = [final hash values...]
```

---

### KROK 2: Weryfikacja - Udowodnienie L2 ∈ Tree

**Cel:** Udowodnić że L2 (index=2) należy do drzewa o root=ROOT

#### 2.1 Zbieranie Siblings

Dla **index=2** (binary `10`):

```
Poziom 0: index=2 → sibling_index=3
  siblings[0] = L3 = [40, 0, 0, 0, 0, 0, 0, 0]

Poziom 1: parent_index=1 → sibling_index=0
  siblings[1] = H01 = [hash of (L0, L1)]
```

**Path to root:**
```
L2 --[hash with L3]--> H23 --[hash with H01]--> ROOT
```

---

### KROK 3: Computing Component Trace Generation

**Depth=2 → 4 aktywne wiersze (2 wiersze per poziom)**

#### ROW 0-1: Poziom 0 (hash L2 with sibling)

**Index bits:** index=2 = `10` binary
- bit[0] = 0 → current goes LEFT, sibling goes RIGHT

**ROW 0 (pierwsza absorpcja):**
```
Level: 0
Is second absorption: NO (level start)
Index bit[0]: 0
Message: L2 (current goes first because bit=0)

Trace columns:
  message[0..8] = [30, 0, 0, 0, 0, 0, 0, 0]

  initial_state[0..16] = [30,0,0,0,0,0,0,0, | 0,0,0,0,0,0,0,0]
                          └─────RATE─────┘   └──CAPACITY=0──┘
                          (Fresh sponge!)

  [Poseidon permutation columns...]

  final_state[0..16] = output0
```

**ROW 1 (druga absorpcja):**
```
Level: 0
Is second absorption: YES
Index bit[0]: 0
Message: siblings[0] = L3 = [40, 0, 0, 0, 0, 0, 0, 0]

Trace columns:
  message[0..8] = [40, 0, 0, 0, 0, 0, 0, 0]

  initial_state[0..16] = [output0[0]+40, output0[1], ..., output0[7] | output0[8], ..., output0[15]]
                          └────add message to rate──────────────┘   └───preserve capacity─────┘

  [Poseidon permutation columns...]

  final_state[0..16] = output1

  ✓ output1[0..8] powinno = H23 (hash z budowania drzewa!)
```

**Update:** `current_node = output1[0..8] = H23`

---

#### ROW 2-3: Poziom 1 (hash H23 with sibling)

**Index bits:** parent_index=1 = `1` binary
- bit[1] = 1 → sibling goes LEFT, current goes RIGHT

**ROW 2 (pierwsza absorpcja - LEVEL START!):**
```
Level: 1
Is second absorption: NO (level start)
Index bit[1]: 1
Message: siblings[1] = H01 (sibling goes first because bit=1)

Trace columns:
  message[0..8] = H01

  initial_state[0..16] = [H01, | 0,0,0,0,0,0,0,0]
                          └─RATE┘ └──CAPACITY=0──┘
                          (Fresh sponge - capacity RESET!)

  [Poseidon permutation columns...]

  final_state[0..16] = output2
```

**ROW 3 (druga absorpcja - LAST ROW!):**
```
Level: 1
Is second absorption: YES
Index bit[1]: 1
Message: current_node = H23

Trace columns:
  message[0..8] = H23

  initial_state[0..16] = [output2[0]+H23[0], ... | output2[8], ...]

  [Poseidon permutation columns...]

  final_state[0..16] = output3

  ✓✓ computed_root = output3[0..8] = ROOT
```

---

### KROK 4: Constraints Verification

#### Computing Component Constraints:

**Constraint 1:** Level start rows have capacity=0
```
ROW 0: is_level_start=1, is_active=1
  → initial_state[8..16] MUST = 0 ✓

ROW 2: is_level_start=1, is_active=1
  → initial_state[8..16] MUST = 0 ✓
```

**Constraint 2:** Chaining within level (odd rows only)
```
ROW 1: enable_chaining = is_active * (1 - is_level_start) = 1 * (1-0) = 1
  → initial_state[0..8] MUST = final_state_prev[0..8] + message ✓
  → initial_state[8..16] MUST = final_state_prev[8..16] ✓

ROW 3: enable_chaining = 1
  → initial_state[0..8] MUST = final_state_prev[0..8] + message ✓
  → initial_state[8..16] MUST = final_state_prev[8..16] ✓
```

**Constraint 3:** Poseidon correctness
```
Wszystkie 4 wiersze: Intermediates match Poseidon computation ✓
```

---

### KROK 5: Scheduler Component

**Trace:** 4 wiersze (wszystkie identyczne)
```
ROW 0, 1, 2, 3:
  computed_root[0..8] = ROOT (otrzymany z Computing)
  expected_root[0..8] = ROOT (public input)
```

**Constraints:**
```
Constraint 1: computed_root == expected_root (all rows) ✓
Constraint 2: values constant across rows ✓
```

---

### KROK 6: LogUp Verification

**Computing yields (ROW 3 only):**
```
Multiplicity: +1 (is_last = 1 only for row 3)
Value: ROOT[0..8]
Contribution: +1 / combine(ROOT)
```

**Scheduler uses (ROW 0 only):**
```
Multiplicity: -1 (is_first = 1 only for row 0)
Value: ROOT[0..8]
Contribution: -1 / combine(ROOT)
```

**Total LogUp sum:**
```
claimed_sum_computing + claimed_sum_scheduler
= (+1 / combine(ROOT)) + (-1 / combine(ROOT))
= 0 ✓✓✓

LogUp property satisfied!
```

---

## ✅ PROOF GENERATED!

Co proof zawiera:
- Commitments do trace'ów (preprocessed, main, interaction)
- FRI proof dla polynomial commitment
- Decommitment paths

Co proof **NIE** ujawnia:
- ❌ Wartości L2 (leaf)
- ❌ Wartości siblings
- ❌ Index
- ✅ Tylko ROOT (public input)

**Verifier:** Sprawdza commitment + constraints → Akceptuje! 🎉

---

## 🔑 Kluczowe Insights

1. **Sponge = Fresh per level:** Capacity resetuje się na początku każdego poziomu (ROW 0, 2)

2. **Chaining within level:** Stan przechodzi między absorpcjami TEGO SAMEGO poziomu (ROW 0→1, ROW 2→3)

3. **Index bits control order:** Decydują czy current czy sibling idzie pierwszy

4. **LogUp = glue:** Computing "yields" root, Scheduler "uses" root → muszą się zgadzać!

5. **Zero-knowledge:** Cały proof nie ujawnia wartości prywatnych, tylko że są poprawne!
