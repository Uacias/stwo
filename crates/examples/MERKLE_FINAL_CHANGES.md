# Merkle Final - Implementacja Użytkownika

## Co się zmieniło

### 1. Siblings są 16-elementowe (rate + capacity)

**Stary sposób:**
```rust
siblings: Vec<[BaseField; RATE]>  // 8 elementów
```

**Nowy sposób:**
```rust
siblings: Vec<[BaseField; N_STATE]>  // 16 elementów (rate + capacity)
```

### 2. Capacity NIE jest resetowane między poziomami

**Stary sposób (capacity reset):**
```rust
Row 2 (level 1 start): initial_state = [H45, 0, 0, 0, 0, 0, 0, 0, 0...]
                                              ↑ capacity = 0 (RESET!)
```

**Nowy sposób (NO reset):**
```rust
Row 2 (level 1 start):
  - Jeśli używamy sibling:   initial_state = [sibling_rate, sibling_capacity]
  - Jeśli używamy current:   initial_state = [current_rate, prev_output_capacity]
                                                             ↑ capacity z poprzedniego poziomu!
```

## Kluczowa różnica

**Standard approach:**
- Hash(A, B) jest niezależny - capacity=0 na starcie
- Proof size: depth × 8 elementów
- Deterministyczny hash

**User's approach (merkle_final):**
- Hash(A, B) używa capacity z A (jeśli A to sibling z capacity)
- Proof size: depth × 16 elementów (2x większy!)
- Hash zależy od capacity A

## Status implementacji

✅ trace_gen.rs - zaktualizowany (NO capacity reset)
✅ mod.rs - prove_merkle signature zmieniony
✅ Test test_merkle_proof - zaktualizowany
⚠️ Pozostałe testy - wymagają aktualizacji (siblings 8→16 elem)

## Przykład użycia

```rust
// Dla depth=3, index=5 (L7):

// Siblings (16 elementów każdy):
let sibling0 = [L6_rate (8), L6_capacity (8)];  // capacity=0 dla leaf
let sibling1 = [H45_rate (8), H45_capacity (8)]; // capacity z hash(L4,L5)
let sibling2 = [H03_rate (8), H03_capacity (8)]; // capacity z hash(L0,L1,L2,L3)

// Trace generation:
// Row 0: Absorb L6 with capacity from sibling0 (=0)
// Row 1: Absorb L7 → H67
// Row 2: Absorb H45 with capacity from sibling1 (NO RESET!)
// Row 3: Absorb H67_rate → H47
// Row 4: Absorb H03 with capacity from sibling2 (NO RESET!)
// Row 5: Absorb H47_rate → ROOT
```

## Trade-offs

| Aspekt | Standard | User's (merkle_final) |
|--------|----------|----------------------|
| **Proof size** | depth × 8 | depth × 16 (2x!) |
| **Determinizm** | Hash(A,B) zawsze taki sam | Zależy od capacity A |
| **Security** | Standard Poseidon | Też secure (niestandardowe) |
| **Rows** | 2 × depth | 2 × depth (bez zmian) |

## Testing

Testy wymagają konwersji siblings z 8→16 elem.

Zaktualizowany test: `test_merkle_proof`
Pozostałe do aktualizacji: test_merkle_proof_simple_value, _two_values, _four_values, _eight_values, _detailed_simulation