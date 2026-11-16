# Reverse-engineering notes: Sins Rebellion Trainer

This is the technical reference for the trainer's **Cheats** tab and **ship hull / shield** tool.
It covers how they work inside the game, every offset and byte pattern, the evidence each one rests
on, and how to update or extend the trainer.

For using the trainer, see [README.md](README.md).

---

## Contents

- [Target](#target)
- [Approach](#approach)
- [How a cheat works, end to end](#how-a-cheat-works-end-to-end)
- [Finding your player](#finding-your-player)
- [The player modifier table](#the-player-modifier-table)
- [Ship hull / shield](#ship-hull--shield)
- [Evidence: game functions behind each feature](#evidence-game-functions-behind-each-feature)
- [Code structure in SinsTrainer.cs](#code-structure-in-sinstrainercs)
- [Apply and restore logic](#apply-and-restore-logic)
- [Approaches that were rejected](#approaches-that-were-rejected)
- [Tools](#tools)
- [Helper scripts](#helper-scripts)
- [Adding a new cheat](#adding-a-new-cheat)
- [Updating for a new game version](#updating-for-a-new-game-version)
- [Troubleshooting the pointer chain](#troubleshooting-the-pointer-chain)

---

## Target

| | |
|---|---|
| Game | Sins of a Solar Empire: Rebellion **v1.98** |
| Executable | `Sins of a Solar Empire Rebellion.exe` |
| Architecture | 32-bit x86 PE, preferred image base `0x400000` |
| ASLR | **Yes** (DYNAMICBASE). The real base changes every launch. |
| Symbols | No PDB, but C++ RTTI class names (`Iron::Player`, `Iron::Frigate`, …) are present. |
| Tested with | The SotP v0.91.0 mod: 27 players per match including neutrals; the local player is index 0. |

All addresses in this document are **v1.98 virtual addresses at the preferred base `0x400000`**.
At runtime, add `(moduleBase - 0x400000)`.

The trainer itself is a **64-bit** process reading a **32-bit** game. Pointers in game memory are
therefore 4 bytes, and the game's module is found with `EnumProcessModulesEx(LIST_MODULES_ALL)`.

---

## Approach

**Cheats** are **data writes, not code patches**. Each one writes a float into the local player's
**research-modifier table**: the same table that in-game research bonuses such as
"+25% build speed" feed into. Because every player has a separate table, writing to the local
player's table affects only you.

This has three advantages over patching game code:
- **Player-only by construction:** no "is this the human player?" check has to be injected into game code.
- **No code is modified,** so a wrong patch can't crash the game.
- **Easy to undo:** restoring means writing the original float back.

The **ship hull / shield** tool is also a data write: it sets one float in the targeted ship.

---

## How a cheat works, end to end

```
attach ─► find game module base (ASLR)
       ─► scan .text for PAT_GAME ─► read the Game global's address from the matched instruction
       ─► scan .text for PAT_SEL  ─► selection / mouse-over globals (ship tool)
every 250 ms:
       ─► walk the pointer chain to the local player's data block P
       ─► check player vtable == Iron::Player vtable (else: refuse, write nothing)
       ─► for each enabled cheat: write P + offset (set to a value, or original + bonus)
       ─► for each cheat just turned off: write the original value back
       ─► refresh the ship readout (ship under mouse, selected ships)
on Apply / Alt+Q / Alt+W:
       ─► target = ship under mouse, else the selected ships ─► write hull or shield float
```

---

## Finding your player

### The pointer chain

```
Game   = [GameGlobal]                    GameGlobal = 0xE22108 in v1.98 (found by pattern, see below)
L      = [Game + 0x570C]                 player list / player manager
count  = [L + 0x2660]                    number of players (includes neutral/pirate/minor factions)
array  = [L + 0x2664]                    pointer to array of Player*
index  = [L + 0x2668]                    LOCAL (human) player index
player = [array + index * 4]             Iron::Player object
check  : [player] == Iron::Player vtable (0x97C524 in v1.98)
P      = player + 0x18                   player data block (what Player vfunc +0x20C returns)
```

**Evidence:**
- `[[Game+0x570C]+0x2668]` appears about **325 times** in the decompiled code as "the local
  player's index". `+0x2660` (count) and `+0x2664` (array) appear next to it in the same shape.
- The ship-request check `FUN_0058e500` indexes `[list+0x2664][playerIndex]` and calls vfunc
  `+0x20C` on the result.
- The `Iron::Player` vtable (from RTTI) is at `0x97C524`. Its slot `+0x20C` points to
  `FUN_004f0db0`, which returns `this + 0x18`. That is why `P = player + 0x18`.
- Only one `Iron::Player` class exists (no human-player subclass), so the exact vtable check
  accepts both human and AI players, and only ever genuine player objects.

### Byte patterns for the Game global

Because of ASLR, the trainer can't hard-code `0xE22108`. It finds an instruction that loads the
global and reads the absolute address from its operand. The loader has already relocated that
operand, so it is the correct runtime address.

| Name | Pattern | Hits in v1.98 | Global at |
|---|---|---|---|
| `PAT_GAME` | `8B 0D ?? ?? ?? ?? 8B 81 0C 57 00 00 8B 80 68 26 00 00` | 1 (`0x4C9422`) | bytes +2..+5 |
| `PAT_GAME_ALT` | `8B 0D ?? ?? ?? ?? 8B 89 0C 57 00 00` | 8 (all agree) | bytes +2..+5 |

`PAT_GAME` decodes as `mov ecx,[Game]` / `mov eax,[ecx+0x570C]` / `mov eax,[eax+0x2668]`, which
is the start of the pointer chain itself. The trainer tries `PAT_GAME` first. If it doesn't match
exactly once, it falls back to `PAT_GAME_ALT` and requires every hit to point to the same global.

### Sanity checks before any write

`GameCheats.LocalPlayerData()` returns 0 (no write) unless:
- the global, the Game object, and `L` are non-null,
- `0 < count <= 64`. **SotP matches have 27 players**: the first version capped this at 16, which
  made the trainer refuse every match.
- `index < count` and the player pointer is non-null,
- the player's vtable equals `moduleBase + 0x57C524` (v1.98 `Iron::Player`).

---

## The player modifier table

The player data block `P` holds a float array of research modifiers:

```
address of modifier = P + 0x410 + type * 4
```

`type` is the enum whose names come from the enum-to-name function `FUN_0065ca70`. The entries the
trainer uses:

| Cheat | Enum name | Type | Offset in `P` | How the game uses it |
|---|---|---|---|---|
| Fast Construction | `ModuleBuildRateAdjustment` | `0x54` | `0x560` | time ÷ (1 + value) |
| Fast Research | `ResearchBuildRateAdjustment` | `0x61` | `0x594` | time ÷ (1 + value) |
| Fast Upgrade | `PlanetUpgradeBuildRateAdjustment` | `0x4D` | `0x544` | time ÷ (1 + value) |
| Fast Production | `ShipBuildRateAdjustment` | `0x69` | `0x5B4` | time ÷ (1 + value) |
| Unlimited Ships (fleet supply) | `ShipMaxSlots` | `0x6B` | `0x5BC` and `0x1B54` | added to max fleet supply |
| Unlimited Ships (capital ships) | `CapitalShipMaxSlots` | `0x21` | `0x494` and `0x1A2C` | floored, gives capital ship limit |

**The ship limits live in two modifier blocks.** A second copy of the block sits at `P + 0x1598`
(`0x5BC` → `0x1B54`, `0x494` → `0x1A2C`, `0x53C` → `0x1AD4`). The slot recalculation at `0x608100`
turns the first copy into the limits the **HUD** shows (`P+0x1D8` fleet, `P+0x258` capital) and the
second copy into the limits the **build checks** use (`P+0x1DC` fleet, `P+0x25C` capital).
`CanRequestShip` (`0x58E500`) computes free supply as `[P+0x1DC] − used` (the used total comes from
`0x606870` on the object at `P+0x1D4`). If only the first copy is raised, the HUD shows the new
limit but every build says "Insufficient Fleet Capacity". The trainer writes both copies.

**Rate formula** (identical in every rate getter):

```
factor = value >= 0 ? 1 + value : 1 / (1 - value)
time   = baseTime / factor
```

So writing **999** gives a factor of 1000, which makes items take 1/1000 of the time.

**Values in a fresh SotP match** (read live): all four rates `0`, `ShipMaxSlots = 100`,
`CapitalShipMaxSlots = 3`.

**The table base was confirmed from the instructions**, not guessed. The research-time getter
(below) reads `P+0x594`, which is enum `0x61` × 4 + `0x410`.

---

## Ship hull / shield

### Which ship: selection and mouse-over globals

Three adjacent globals (v1.98):

| Address | Meaning |
|---|---|
| `0xDF08E4` | Pointer to the **selection list** head node (circular doubly linked list) |
| `0xDF08E8` | Number of selected entities |
| `0xDF08EC` | **Entity under the mouse cursor** (the "highlighted" entity), or 0 |

List node layout: `{ next, prev, Entity* }`, so the entity is at `node + 8`. Walk from
`[head]` until you're back at `head`.

**Evidence:**
- The developer debug menu's "all selected entities" base class (`AllSelectedEntitiesDebugMenuItem`;
  the Damage and Kill items derive from it) runs its action through `FUN_004e44f0`. That function
  walks the list at `[0xDF08E4]` and calls the action with `node[2]` for every node.
- The mouse-click handler `FUN_004b0da0` (it handles the `"CursorUp"` event) does: if
  `[0xDF08EC] == 0` and `[0xDF08E8] > 0`, use the first selected entity, else use `[0xDF08EC]`.
  That is "entity under cursor, otherwise the selection".
- The static initializer at `0x401F40` creates the empty list in `0xDF08E4` and zeroes `0xDF08EC`.

**Byte patterns** (both unique in v1.98; the trainer requires both to agree):

| Name | Pattern | Value |
|---|---|---|
| `PAT_SEL` | `A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 00 A1 ?? ?? ?? ?? 89 40 04 C7 05 ?? ?? ?? ?? 00 00 00 00` | selection at +1, hover at +22 (must be selection + 8) |
| `PAT_SEL_ALT` | `A1 ?? ?? ?? ?? 53 56 57 8B 30 8B F9 3B F0 74 1E` | selection at +1 (inside `FUN_004e44f0`) |

If these don't match, the trainer disables only the ship tool ("not available for this game
version"); the cheats keep working.

### Hull and shield inside a ship

Every combat entity has a damage block holding the current hull and shield floats:

```
hull   = entity + block + 0x0C     (float)
shield = entity + block + 0x10     (float)
```

`block` depends on the entity class, so the trainer identifies the class by its primary vtable:

| Class | Primary vtable | Block offset | Hull | Shield |
|---|---|---|---|---|
| `Iron::Frigate` | `0x982764` | `0x580` | `+0x58C` | `+0x590` |
| `Iron::CapitalShip` | `0x983E70` | `0x5C0` | `+0x5CC` | `+0x5D0` |
| `Iron::Titan` | `0x9795D8` | `0x574` | `+0x580` | `+0x584` |
| `Iron::StarBase` | `0x97A794` | `0x638` | `+0x644` | `+0x648` |
| `Iron::Fighter` | `0x978FC8` | `0x400` | `+0x40C` | `+0x410` |
| `Iron::SpaceMine` | `0x97B188` | `0x3C0` | `+0x3CC` | `+0x3D0` |

Any other vtable (planets, asteroids, unknown objects) is never written.

**Evidence: two independent sources agree on every class.**
1. **Save-game serializer:** `FUN_0055b860` saves `"CurrentHullPoints"` from `this+0x0C` and
   `"CurrentShieldPoints"` from `this+0x10`. Each class's serializer calls it with
   `lea ecx,[edi+X]`. Frigate uses X = `0x53C`, inside a sub-object at `this + 0x44` (from RTTI),
   so `0x44 + 0x53C = 0x580`.
2. **Damage-component getter:** Entity vfunc `+0xBC`, which the developer Damage action calls to
   get the damage target, returns `this + 0x580` for Frigate, `+0x5C0` for CapitalShip, and so on.
   These are the same numbers.

---

## Evidence: game functions behind each feature

Addresses are v1.98 at base `0x400000`; names are Ghidra defaults.

| Function | What it is | Key evidence |
|---|---|---|
| `0x58B860` | Research time getter | `(level*[subj+0x590] + [subj+0x58C])` ÷ research game-speed scalar `[0xF0A190 + idx*8]` ÷ `(1 + [P+0x594])` |
| `0x590C80` | Ship build request / time | reads `P+0x5B4` (ship build rate) and the ship game-speed scalar `0xF0A128` |
| `0x518E10` | Module build time | `local * 1/(1 + [P+0x560])` |
| `0x5AFFF0` | Module build time (planet) | calls the planet modifier lookup with `0xD` (`ModuleBuildRatePerc`) |
| `0x525D80` | Module build time (IBuildOverTime) | divides by `(1 + module build scalar [0xF0A12C + idx*0xC])` |
| `0x5BAC00` | Planet upgrade time | reads `P+0x544`, planet modifier `0xF` (`PlanetUpgradeBuildRatePerc`) |
| `0x59FA90` | Upgrade stage time | `stage*0x87C + 0x1C` base time |
| `0x608100` | Ship-slot limit recalculation | `maxFleet = (base + [P+0x5BC]) * (1 + [P+0x53C]) * fleetSupplyScalar`; capital = `floor([P+0x494])` |
| `0x58E500` | CanRequestShip (frigate) | returns status 8 "not enough ship slots" when free supply < cost |
| `0x58E910` / `0x58EC70` | CanRequestShip (capital / titan) | |
| `0x58F220` | Capital ship slot check | `[P+0x25C]` (int) − count of `[P+0x260]` |
| `0x6FFD60` | CanRequestShip status → text | maps 0–12 to `IDS_CANREQUESTSHIPSTATUS_*` (8 = ship slots, 9 = capital slots) |
| `0x65CA70` | Player modifier enum → name | source of the type numbers in the modifier table |
| `0x581480` | Planet modifier enum → name | `0xD` ModuleBuildRatePerc, `0xF` PlanetUpgradeBuildRatePerc |
| `0x55B860` | Damage block serializer | `CurrentHullPoints` at `+0x0C`, `CurrentShieldPoints` at `+0x10` |
| `0x4E44F0` | Debug "all selected entities" loop | walks the selection list at `[0xDF08E4]` |
| `0x4E4FB0` | Debug "Damage" action | gets the damage component through Entity vfunc `+0xBC` |
| `0x4B0DA0` | Mouse click handler | entity under cursor `[0xDF08EC]`, otherwise the first selected entity |

Static data:

| Address | What |
|---|---|
| `0xE22108` | Game global |
| `0xDF08E4` / `0xDF08E8` / `0xDF08EC` | Selection list / selected count / entity under cursor |
| `0xF0A124` | `FixedArray<BuildSpeedData,4>` (stride `0xC`: vtable, ship scalar `+4`, module scalar `+8`) |
| `0xF0A18C` | `FixedArray<ResearchSpeedData,4>` (stride 8, scalar `+4`) |
| `[[Game]+0x210]+0xB88` | Built-in "no slot restrictions" developer flag (applies to all players, not used) |

---

## Code structure in SinsTrainer.cs

| Part | Role |
|---|---|
| `Native` | Win32 imports: `OpenProcess`, `ReadProcessMemory`, `WriteProcessMemory`, `VirtualQueryEx`, and psapi `EnumProcessModulesEx` / `GetModuleFileNameExW` / `GetModuleInformation`. |
| `Mem` | Process memory access. Scan helpers for the Resources and Advanced tabs, plus `ReadU32` / `ReadF32` / `WriteF32`, `MainModule()` (32-bit module from a 64-bit process) and `FindPattern()` (IDA-style `??` wildcards). |
| `SinsOffsets` | **All version-specific constants**: patterns, chain offsets, vtable RVAs, modifier offsets and the ship class table. Change these for a new game version. |
| `ShipClass` / `ShipTarget` | A ship class (name, vtable RVA, damage block offset), and one targeted ship with its hull and shield addresses. |
| `CheatField` | One float to write: `Offset`, `Additive` (bonus vs. set), `Value` or `ValueFn`, and the remembered original. |
| `Cheat` | A named cheat: its fields, plus either a checkbox or an `IsOn` function (for the number boxes). |
| `GameCheats` | `Define()` lists the cheats; `Init()` finds the module and globals; `LocalPlayerData()` walks the chain; `Tick()` applies or restores; `RestoreAll()` runs on close; `Hovered()` / `Selected()` / `Targets()` find ships. |
| `TrainerForm.BuildCheatsTab` | The Cheats tab UI, including the ship-limit number boxes. |
| `TrainerForm.BuildShipBox` / `ApplyShip` | The ship hull / shield box and its Apply logic. |
| `TrainerForm.WndProc` | Global hotkeys (`RegisterHotKey`): Alt+Q, Alt+W, Alt+1..4. |
| `TrainerForm.Tick` | 250 ms timer: runs `cheats.Tick()`, the ship readout, and the scan tabs' freeze logic. |

The Unlimited Ships checkbox is a **preset** for the same two fields as the number boxes
("Extra fleet supply" and "Extra capital ship slots"). Their `ValueFn` returns 2000 / 20 while the
checkbox is ticked, and otherwise the box values. This way the two can never stack bonuses on
the same game value.

---

## Apply and restore logic

For each field of an enabled cheat, every 250 ms:

```
cur = read P+offset
if not remembered, or cur != lastWritten:      # first time, or the game recalculated it
    orig = cur                                 # e.g. a research just changed this bonus
want = additive ? orig + value : value
if cur != want: write want
lastWritten = want
```

When a cheat is turned off: if `cur == lastWritten`, write `orig` back; then forget it.
When the player object changes (new match or loaded save): forget everything, and don't restore
into the new object. On trainer close: `RestoreAll()`.

The ship hull / shield tool is a **one-time write** with nothing to restore. The game's own damage
and regeneration take over afterwards.

---

## Approaches that were rejected

| Approach | Why not |
|---|---|
| Copying logic from WeMod/Wand trainer modules | Those DLLs are packed: their code section is empty on disk and only decrypted at runtime. Unpacking them would mean defeating a commercial product's protection, so the game was reverse-engineered directly instead. Their feature list was used only as a wish list. |
| The game's dev flag `[[Game]+0x210]+0xB88` ("no slot restrictions") | It is read by 8 functions and lifts limits for **every** player, AI included. |
| Code caves in the CanRequestShip checks | Possible (the player is in `ESI` at `0x58E7EC`), but more fragile and riskier than writing data. |
| Changing the global BuildSpeed/ResearchSpeed tables (`0xF0A124` / `0xF0A18C`) | Global: they would speed up the AI too. |
| Freezing max fleet supply at `P+0x1DC` / `P+0x25C` | The game rewrites these during recalculation; writing the modifier is what feeds that calculation. |

---

## Tools

| Tool | Used for |
|---|---|
| [REA](https://github.com/morluto/rea) (npm `rea-agents`) | MCP server that drives Ghidra from an AI coding agent: `open_binary`, `procedure_pseudo_code`, `procedure_assembly`, `decompile_all`, `xrefs`. |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) 12.x | Disassembly and decompilation. Ghidra 12.2 needs a 64-bit **JDK 25**. A full auto-analysis of the game takes about 6 minutes. |
| Node.js 22+/24+ | The helper scripts in `tools/`. |

Recreating the Ghidra project from the command line:

```bat
set JAVA_HOME=<path to JDK 25>
<ghidra folder>\support\analyzeHeadless.bat <project folder> SinsRebellion ^
  -import "<game folder>\Sins of a Solar Empire Rebellion.exe" -max-cpu 6
```

---

## Helper scripts

The `tools/` folder holds small Node.js scripts used during the analysis. Set two environment
variables first:

| Variable | Meaning |
|---|---|
| `SINS_EXE` | Full path to `Sins of a Solar Empire Rebellion.exe`. Needed by `pattern`, `vt`, `owner`. |
| `SINS_DECOMP` | Folder with the decompiled functions (`functions\*.c` from REA `decompile_all`). Needed by `make-all`, `q`, `at`. Default: `.\sins_decomp`. |

| Script | Usage | What it does |
|---|---|---|
| `pattern.js` | `node pattern.js` | Checks every byte pattern the trainer uses against `SINS_EXE` and prints the globals they resolve to. **Run this first after a game update.** |
| | `node pattern.js "8B 0D ?? ?? ?? ??"` | Prints all matches of any pattern. |
| `make-all.js` | `node make-all.js` | Joins `functions\*.c` into one `all.c` for fast searching. |
| `q.js` | `node q.js find <regex>...` | Functions whose pseudocode matches all the regexes. |
| | `node q.js show 58b860` | Prints one function. |
| | `node q.js calls FUN_006ffd60` | Functions that call it. |
| `at.js` | `node at.js 58b89a` | Which function contains an address. |
| `vt.js` | `node vt.js ".?AVPlayer@Iron@@" 20c` | A class's vtables (from RTTI) and selected slots. The row with `thisOff=0x0` is the primary vtable. |
| `owner.js` | `node owner.js 4e4fb0` | Which class's vtable contains a function, and at which slot. |

Example (PowerShell):

```powershell
$env:SINS_EXE = "<game folder>\Sins of a Solar Empire Rebellion.exe"
$env:SINS_DECOMP = "<folder with decompile output>"
node tools\pattern.js
```

The decompiled output is derived from the game's own code, so it is excluded from the repository
by `.gitignore`. Generate it locally.

---

## Adding a new cheat

If the effect is a player research modifier, adding it takes a few lines:

1. Find the enum type in `FUN_0065ca70`:
   ```
   node tools\q.js show 65ca70
   ```
   Examples: `0x26` ExtractionRateMetalAdjustment, `0x4F` PopulationGrowthRateAdjustment,
   `0x62` ResearchCostAdjustment.
2. The offset is `0x410 + type * 4`.
3. Confirm the game reads it as a float from `P`. Search the raw code for `movss`/`addss`/`comiss`
   with that displacement, as was done for `0x594`/`0x5B4`/`0x560`/`0x544`, and read the containing
   function with `node tools\at.js <addr>` and `node tools\q.js show <func>`.
4. Add a constant to `SinsOffsets` and a line to `GameCheats.Define()`, for example:
   ```csharp
   Cheats.Add(new Cheat { Name = "Fast Metal", Help = "...",
       Fields = new[] { Set(SinsOffsets.MOD_METAL_EXTRACTION, 10f) } });
   ```
   Use `Set(...)` for rates and `Add(...)` for bonuses that stack on the game's own value.
5. Build and test in a skirmish. Before trusting a new field, read its live value first: it
   should be small and sensible, like the `0` / `100` / `3` seen above.

For a new **per-ship** value (for example experience or antimatter), find its save-game name with
`node tools\q.js find "L\"<Name>\""`, take the offset from that serializer, and add the
`lea ecx,[edi+X]` / sub-object (`thisOff`) adjustment exactly as done for hull and shield.

Cheats that are in neither table (for example, god mode for every ship) need new analysis. Start
from a related string or RTTI class and use `q.js` / `vt.js` / `owner.js`.

---

## Updating for a new game version

When the game updates, the status line shows `unexpected game version` or `pattern not found`,
and the ship box says the tools are not available. Nothing is written. To update:

1. **Check the patterns:** `node tools\pattern.js` against the new exe. If every pattern still
   matches once and points to sensible globals, continue with step 3.
2. **Re-run the analysis** if patterns fail: run Ghidra (command above), then in an AI agent with
   REA, `open_binary` the exe, `decompile_all` to a folder, and run `node tools\make-all.js`.
   Find new patterns near the same code. For example, search `all.c` for `+ 0x2668)`-style
   local-index reads, or for the selection list loop of the "all selected entities" debug item.
3. **Player vtable:** `node tools\vt.js ".?AVPlayer@Iron@@" 20c`. Use the row with `thisOff=0x0`
   and set `PLAYER_VTABLE_RVA = vtable - 0x400000`. Check that slot `+0x20C` still returns `this+0x18`.
4. **Ship classes:** `node tools\vt.js ".?AVFrigate@Iron@@" bc`, and the same for the other classes.
   Take the `thisOff=0x0` vtable, read the `+0xBC` getter with `q.js show`, and update
   `SHIP_CLASSES` (vtable RVA and block offset).
5. **Modifier offsets:** dump the enum with `q.js show` on the new enum-to-name function (search for
   `"ShipBuildRateAdjustment"`), and confirm the table base from the research-time getter, which
   reads the research game-speed scalar. Update `SinsOffsets`.
6. Build, then check the live values with a read-only test before enabling writes.

---

## Troubleshooting the pointer chain

A read-only diagnostic program was used to find the "27 players" bug. To repeat it:

1. Find the module base with `EnumProcessModulesEx`.
2. `G = moduleBase - 0x400000 + 0xE22108`, then print `[G]`, `[Game+0x570C]`,
   `[L+0x2660]`, `[L+0x2664]` and `[L+0x2668]`.
3. Print each `array[i]` and its vtable, and compare against `moduleBase - 0x400000 + 0x97C524`.
4. Print the local player's modifier floats (`P+0x494`, `+0x544`, `+0x560`, `+0x594`, `+0x5B4`, `+0x5BC`).
5. For the ship tool: print `[Sel]`, `[Sel+4]` and `[Sel+8]` (`Sel = moduleBase - 0x400000 + 0xDF08E4`)
   while hovering over or selecting a ship.

Known results (v1.98 + SotP, skirmish): count `0x1B` (27), local index `0`, and every player's
vtable equals the `Iron::Player` vtable.

If "no match running" shows during a match again, the most likely causes are a mod with even more
players (raise the 64 cap in `LocalPlayerData`) or a different game build (see
[Updating for a new game version](#updating-for-a-new-game-version)).
