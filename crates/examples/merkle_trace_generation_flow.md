# Merkle Trace Generation - Hash & Absorption Flow

**Focus:** Jak generujemy trace - co hashujemy, w jakiej kolejności, jak działa absorpcja

## Setup

```
Drzewo (depth=3, 8 liści):
                ROOT
             /        \
          H03          H47
         /   \        /   \
       H01   H23    H45   H67
      / \   / \    / \   / \
     L0 L1 L2 L3  L4 L5 L6 L7
                      ↑
                  index=5 (binary: 101)

Weryfikujemy: L5 ∈ Tree
Siblings: [L4, H67, H03]
```

---

## Kluczowa Koncepcja: Sponge Construction

**Każdy poziom Merkle = 2 absorpcje (2 rows):**
1. **First absorption (even row):** Absorb pierwszy węzeł, **capacity = 0**
2. **Second absorption (odd row):** Absorb drugi węzeł, **capacity preserved** z poprzedniego row

**Poseidon state = 16 elementów:**
- Rate (0-7): 8 elementów - tu wchodzi/wychodzi message
- Capacity (8-15): 8 elementów - wewnętrzny stan dla security

---

## Row 0: Level 0, First Absorption - Absorb L4

### Przygotowanie

```rust
current_node = L5 (początkowy leaf)
level = 0
index_bit = (5 >> 0) & 1 = 1 (L5 na RIGHT)
```

### Co absorbujemy?

```
index_bit = 1 → L4 first, L5 second
message = siblings[0] = L4
```

### Budujemy initial_state

```
Pierwszy row (row==0) → special case:
initial_state = [message, zeros]

rate[0-7]:     [L4, L4, L4, L4, L4, L4, L4, L4]
capacity[8-15]: [0,  0,  0,  0,  0,  0,  0,  0]  ← Fresh sponge
```

### Hashujemy (Poseidon)

```
final_state = Poseidon(initial_state)

Przykładowy output:
rate[0-7]:     [123, 456, 789, 234, 567, 890, 345, 678]
capacity[8-15]: [111, 222, 333, 444, 555, 666, 777, 888]
```

### Zapisujemy do trace

```
Kolumny:
- message[0..8]: L4 wartości
- initial_state[0..16]: [L4..., 0...]
- intermediate states: (z Poseidon rounds)
- final_state[0..16]: [123, 456, ..., 888]
```

### Stan na koniec row 0

```
prev_output = final_state (wszystkie 16 elem)
current_node = L5 (bez zmian, bo to even row)
```

---

## Row 1: Level 0, Second Absorption - Absorb L5

### Przygotowanie

```
level = 0
index_bit = 1 (L5 na RIGHT)
```

### Co absorbujemy?

```
index_bit = 1 → current second
message = current_node = L5
```

### Budujemy initial_state - CHAINING!

```
Nieparzyste row (odd) → chaining z poprzedniego:
initial_state = [prev_rate + message, prev_capacity]

rate[0-7]:     [123+L5, 456+L5, 789+L5, 234+L5, 567+L5, 890+L5, 345+L5, 678+L5]
                ↑ Absorbujemy L5 do rate!
capacity[8-15]: [111, 222, 333, 444, 555, 666, 777, 888]
                ↑ Capacity preserved z row 0!
```

**Kluczowe:** To jest **druga absorpcja tego samego hash'a**! Poseidon sponge wymaga 2 absorpcji dla każdej pary.

### Hashujemy (Poseidon)

```
final_state = Poseidon(initial_state)

Przykładowy output (to jest H45!):
rate[0-7]:     [H45₀, H45₁, H45₂, H45₃, H45₄, H45₅, H45₆, H45₇]
capacity[8-15]: [Cap₀, Cap₁, Cap₂, Cap₃, Cap₄, Cap₅, Cap₆, Cap₇]
```

### Zapisujemy do trace

```
Kolumny:
- message[0..8]: L5 wartości
- initial_state[0..16]: [123+L5, 456+L5, ..., 888]
- intermediate states: (z Poseidon rounds)
- final_state[0..16]: [H45₀, ..., H45₇, Cap₀, ..., Cap₇]
```

### Stan na koniec row 1

```
prev_output = final_state (wszystkie 16 elem)
current_node = final_state[0..8] = [H45₀, H45₁, ..., H45₇]  ← Tylko rate!
               ↑ To będzie użyte w następnym poziomie!
```

**✅ Level 0 skończony: Hash(L4, L5) = H45**

---

## Row 2: Level 1, First Absorption - Absorb H45

### Przygotowanie

```
current_node = H45 (z poprzedniego poziomu)
level = 1
index_bit = (5 >> 1) & 1 = 0 (H45 na LEFT)
```

### Co absorbujemy?

```
index_bit = 0 → H45 first, H67 second
message = current_node = H45
```

### Budujemy initial_state - CAPACITY RESET!

```
Parzyste row + level start → FRESH SPONGE:
initial_state = [message, zeros]

rate[0-7]:     [H45₀, H45₁, H45₂, H45₃, H45₄, H45₅, H45₆, H45₇]
capacity[8-15]: [0, 0, 0, 0, 0, 0, 0, 0]  ← RESET! Nowy poziom!
```

**Kluczowe:** Capacity jest **wyzerowane**! To jest nowy poziom Merkle, więc nowy hash (niezależny od poprzedniego).

**NIE hashujemy samego H45!** To jest pierwsza absorpcja pary (H45, H67).

### Hashujemy (Poseidon)

```
final_state = Poseidon(initial_state)

Przykładowy output:
rate[0-7]:     [Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7]
capacity[8-15]: [D0, D1, D2, D3, D4, D5, D6, D7]
```

### Zapisujemy do trace

```
Kolumny:
- message[0..8]: H45 wartości
- initial_state[0..16]: [H45₀, ..., H45₇, 0, ..., 0]
- intermediate states: (z Poseidon rounds)
- final_state[0..16]: [Y0, ..., Y7, D0, ..., D7]
```

### Stan na koniec row 2

```
prev_output = final_state (wszystkie 16 elem)
current_node = H45 (bez zmian, bo to even row)
```

---

## Row 3: Level 1, Second Absorption - Absorb H67

### Przygotowanie

```
level = 1
index_bit = 0 (H45 na LEFT)
```

### Co absorbujemy?

```
index_bit = 0 → sibling second
message = siblings[1] = H67
```

### Budujemy initial_state - CHAINING!

```
Nieparzyste row → chaining z row 2:
initial_state = [prev_rate + message, prev_capacity]

rate[0-7]:     [Y0+H67₀, Y1+H67₁, Y2+H67₂, Y3+H67₃, Y4+H67₄, Y5+H67₅, Y6+H67₆, Y7+H67₇]
                ↑ Absorbujemy H67 do rate!
capacity[8-15]: [D0, D1, D2, D3, D4, D5, D6, D7]
                ↑ Capacity preserved z row 2!
```

### Hashujemy (Poseidon)

```
final_state = Poseidon(initial_state)

Przykładowy output (to jest H47!):
rate[0-7]:     [H47₀, H47₁, H47₂, H47₃, H47₄, H47₅, H47₆, H47₇]
capacity[8-15]: [Cap₀, Cap₁, Cap₂, Cap₃, Cap₄, Cap₅, Cap₆, Cap₇]
```

### Zapisujemy do trace

```
Kolumny:
- message[0..8]: H67 wartości
- initial_state[0..16]: [Y0+H67₀, ..., D7]
- intermediate states: (z Poseidon rounds)
- final_state[0..16]: [H47₀, ..., H47₇, Cap₀, ..., Cap₇]
```

### Stan na koniec row 3

```
prev_output = final_state (wszystkie 16 elem)
current_node = final_state[0..8] = [H47₀, H47₁, ..., H47₇]  ← Tylko rate!
```

**✅ Level 1 skończony: Hash(H45, H67) = H47**

---

## Row 4: Level 2, First Absorption - Absorb H03

### Przygotowanie

```
current_node = H47 (z poprzedniego poziomu)
level = 2
index_bit = (5 >> 2) & 1 = 1 (H47 na RIGHT)
```

### Co absorbujemy?

```
index_bit = 1 → H03 first, H47 second
message = siblings[2] = H03
```

### Budujemy initial_state - CAPACITY RESET!

```
Parzyste row + level start → FRESH SPONGE:
initial_state = [message, zeros]

rate[0-7]:     [H03₀, H03₁, H03₂, H03₃, H03₄, H03₅, H03₆, H03₇]
capacity[8-15]: [0, 0, 0, 0, 0, 0, 0, 0]  ← RESET! Nowy poziom!
```

**Kluczowe:** Znowu capacity reset! To jest nowy poziom, więc nowy niezależny hash.

### Hashujemy (Poseidon)

```
final_state = Poseidon(initial_state)

Przykładowy output:
rate[0-7]:     [Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7]
capacity[8-15]: [E0, E1, E2, E3, E4, E5, E6, E7]
```

### Zapisujemy do trace

```
Kolumny:
- message[0..8]: H03 wartości
- initial_state[0..16]: [H03₀, ..., H03₇, 0, ..., 0]
- intermediate states: (z Poseidon rounds)
- final_state[0..16]: [Z0, ..., Z7, E0, ..., E7]
```

### Stan na koniec row 4

```
prev_output = final_state (wszystkie 16 elem)
current_node = H47 (bez zmian, bo to even row)
```

---

## Row 5: Level 2, Second Absorption - Absorb H47 (FINAL!)

### Przygotowanie

```
level = 2
index_bit = 1 (H47 na RIGHT)
```

### Co absorbujemy?

```
index_bit = 1 → current second
message = current_node = H47
```

### Budujemy initial_state - CHAINING!

```
Nieparzyste row → chaining z row 4:
initial_state = [prev_rate + message, prev_capacity]

rate[0-7]:     [Z0+H47₀, Z1+H47₁, Z2+H47₂, Z3+H47₃, Z4+H47₄, Z5+H47₅, Z6+H47₆, Z7+H47₇]
                ↑ Absorbujemy H47 do rate!
capacity[8-15]: [E0, E1, E2, E3, E4, E5, E6, E7]
                ↑ Capacity preserved z row 4!
```

### Hashujemy (Poseidon)

```
final_state = Poseidon(initial_state)

Przykładowy output (to jest ROOT!):
rate[0-7]:     [ROOT₀, ROOT₁, ROOT₂, ROOT₃, ROOT₄, ROOT₅, ROOT₆, ROOT₇]
capacity[8-15]: [Cap₀, Cap₁, Cap₂, Cap₃, Cap₄, Cap₅, Cap₆, Cap₇]
```

### Zapisujemy do trace

```
Kolumny:
- message[0..8]: H47 wartości
- initial_state[0..16]: [Z0+H47₀, ..., E7]
- intermediate states: (z Poseidon rounds)
- final_state[0..16]: [ROOT₀, ..., ROOT₇, Cap₀, ..., Cap₇]
```

### Stan na koniec row 5

```
prev_output = final_state (wszystkie 16 elem)
current_node = final_state[0..8] = [ROOT₀, ROOT₁, ..., ROOT₇]
computed_root = final_state[0..8] = [ROOT₀, ROOT₁, ..., ROOT₇]  ← FINAL!
```

**✅ Level 2 skończony: Hash(H03, H47) = ROOT**

---

## Podsumowanie: Co zostało zahashowane?

### Chronologicznie:

```
Row 0-1: Poseidon([L4, 0...]) → state1
         Poseidon([state1_rate + L5, state1_capacity]) → H45

Row 2-3: Poseidon([H45, 0...]) → state2
         Poseidon([state2_rate + H67, state2_capacity]) → H47

Row 4-5: Poseidon([H03, 0...]) → state3
         Poseidon([state3_rate + H47, state3_capacity]) → ROOT
```

### Kluczowe mechanizmy:

#### 1. **Każdy poziom = 2 Poseidon calls (2 absorpcje)**

```
Level 0: Hash(L4, L5)    → 2 Poseidon calls → H45
Level 1: Hash(H45, H67)  → 2 Poseidon calls → H47
Level 2: Hash(H03, H47)  → 2 Poseidon calls → ROOT

Total: 6 Poseidon calls = 6 rows
```

#### 2. **Capacity reset pattern**

```
Row 0: capacity = 0       ← Fresh sponge (level 0 start)
Row 1: capacity preserved ← Same hash continuation
Row 2: capacity = 0       ← Fresh sponge (level 1 start)
Row 3: capacity preserved ← Same hash continuation
Row 4: capacity = 0       ← Fresh sponge (level 2 start)
Row 5: capacity preserved ← Same hash continuation
```

**Pattern:** RESET na parzystych rows (0, 2, 4) = nowy poziom = nowy niezależny hash

#### 3. **Message flow (index=5, binary 101)**

```
Row 0: L4  (siblings[0], bo bit0=1 → sibling first)
Row 1: L5  (current_node, bo bit0=1 → current second)
       ↓
       H45 saved to current_node

Row 2: H45 (current_node, bo bit1=0 → current first)
Row 3: H67 (siblings[1], bo bit1=0 → sibling second)
       ↓
       H47 saved to current_node

Row 4: H03 (siblings[2], bo bit2=1 → sibling first)
Row 5: H47 (current_node, bo bit2=1 → current second)
       ↓
       ROOT saved to computed_root
```

#### 4. **current_node propagation**

```
Start:      current_node = L5 (leaf)
After row 1: current_node = H45[0..8] (tylko rate!)
After row 3: current_node = H47[0..8] (tylko rate!)
After row 5: current_node = ROOT[0..8] (tylko rate!)
```

**current_node zawsze = tylko rate (8 elem), NIE capacity!**

---

## Wizualizacja Flow

```
INPUT: leaf=L5, siblings=[L4, H67, H03], index=5

┌─────────────────────────────────────────┐
│ LEVEL 0 (rows 0-1)                      │
├─────────────────────────────────────────┤
│ Row 0: Absorb L4                        │
│   initial_state = [L4, 0...]            │
│   Poseidon → state                      │
│                                         │
│ Row 1: Absorb L5                        │
│   initial_state = [state_rate+L5, cap]  │
│   Poseidon → H45                        │
│   current_node = H45[rate]              │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ LEVEL 1 (rows 2-3)                      │
├─────────────────────────────────────────┤
│ Row 2: Absorb H45 (capacity RESET!)     │
│   initial_state = [H45, 0...]           │
│   Poseidon → state                      │
│                                         │
│ Row 3: Absorb H67                       │
│   initial_state = [state_rate+H67, cap] │
│   Poseidon → H47                        │
│   current_node = H47[rate]              │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│ LEVEL 2 (rows 4-5)                      │
├─────────────────────────────────────────┤
│ Row 4: Absorb H03 (capacity RESET!)     │
│   initial_state = [H03, 0...]           │
│   Poseidon → state                      │
│                                         │
│ Row 5: Absorb H47                       │
│   initial_state = [state_rate+H47, cap] │
│   Poseidon → ROOT                       │
│   computed_root = ROOT[rate]            │
└─────────────────────────────────────────┘
              ↓
         OUTPUT: ROOT
```

---

## Odpowiedzi na kluczowe pytania:

### Q1: Czy hashujemy pojedyncze wartości (np. samo H45)?
**NIE!** Zawsze hashujemy PARY w dwóch absorpcjach:
- Row 2 to PIERWSZA absorpcja Hash(H45, H67)
- Row 3 to DRUGA absorpcja Hash(H45, H67)
- Dopiero po row 3 mamy pełny hash

### Q2: Dlaczego resetujemy capacity?
Bo każdy poziom Merkle to **niezależny hash**:
- Hash(L4, L5) musi być niezależny od Hash(H45, H67)
- Reset capacity = fresh sponge = nowy hash

### Q3: Co to znaczy "absorpcja"?
Absorpcja w sponge construction:
1. **Pierwsza absorpcja:** `[message1, 0...] → Poseidon → state`
2. **Druga absorpcja:** `[state_rate + message2, state_capacity] → Poseidon → output`

Dwie absorpcje = jeden kompletny hash pary węzłów.

### Q4: Skąd bierze się message w każdym row?
Z kombinacji `current_node` (hash z poprzedniego poziomu) i `siblings[level]` (sibling z tego poziomu).
Kolejność zależy od `index_bit`:
- bit=0 → current first, sibling second
- bit=1 → sibling first, current second

### Q5: Co jest zapisywane w current_node?
**Tylko rate (8 elementów)** z final_state po nieparzystych rows:
- Capacity NIE jest zachowywany w current_node
- current_node to "hash output" z poprzedniego poziomu
- Używany jako input do następnego poziomu
