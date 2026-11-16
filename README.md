# Sins Rebellion Trainer

A single-player trainer for **Sins of a Solar Empire: Rebellion** (v1.98, works with the SotP mod).
It gives you WeMod/Wand-style cheats such as fast construction, fast research and extra ship slots.
It applies them to **your player only**, so the AI opponents are never changed. It also has a ship
tool that sets the hull or shield of the ship under your mouse.

> Use it only in single-player or in games against the AI. In online multiplayer it would desync
> the game, because it changes values on your PC only.

---

## Contents

- [Files in this folder](#files-in-this-folder)
- [Requirements](#requirements)
- [Building](#building)
- [Quick start](#quick-start)
- [Cheats tab](#cheats-tab)
- [Ship hull / shield](#ship-hull--shield)
- [Hotkeys](#hotkeys)
- [Resources tab](#resources-tab)
- [Does it affect the AI?](#does-it-affect-the-ai)
- [Troubleshooting](#troubleshooting)
- [Safety notes](#safety-notes)
- [For developers](#for-developers)

---

## Files in this folder

| File | What it is |
|---|---|
| `SinsTrainer.cs` | The whole trainer source code (one C# file, Windows Forms). |
| `SinsTrainer.exe` | The built trainer. Not stored in the repo: download `SinsTrainer.zip` from the [Releases](../../releases) page, or build it yourself with `build.bat`. |
| `build.bat` | Builds `SinsTrainer.exe` from `SinsTrainer.cs`. |
| `README.md` | This guide. |
| `REVERSE_ENGINEERING.md` | Technical notes: how the cheats work inside the game and how to update them. |
| `tools/` | Node.js helper scripts used for the analysis (see [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md#helper-scripts)). Not needed to use the trainer. |
| `.gitignore` | Keeps local backups and decompiled game files out of the repository. |

---

## Requirements

- Windows 10 or 11 (64-bit).
- .NET Framework 4.x. It is already part of Windows, so nothing extra needs installing.
- *Sins of a Solar Empire: Rebellion* **v1.98**. The Cheats tab checks the game version and refuses
  any other version. The Resources tab works with any version.

---

## Download

Grab the latest `SinsTrainer.zip` from the [Releases](../../releases) page and extract it. Each release
is tagged with a version (`v1.0.0`, `v1.1.0`, ...), so you can also download older builds.

## Building

Double-click **`build.bat`**, or run it from a terminal:

```bat
build.bat
```

It uses the C# compiler that ships with Windows
(`%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`) and writes `SinsTrainer.exe`.

> **Close the trainer before building.** Windows can't overwrite `SinsTrainer.exe` while it is
> running, and the build fails with "The process cannot access the file".

---

## Quick start

1. Start the game and **start or load a match**: a skirmish or a saved game.
2. Alt-Tab and run `SinsTrainer.exe`.
   If attaching fails, right-click the exe and choose **Run as administrator**.
3. Choose the game in **Game process** (click **Refresh** if it isn't listed) and click **Attach**.
   The label turns green: `Attached: Sins of a Solar Empire Rebellion`.
4. On the **Cheats** tab, tick what you want. The status line should turn green:
   `Active on your player (N cheats on).`
5. Go back to the game and play.

**Save your game the first time you try a cheat**, just in case.

---

## Cheats tab

These cheats need no scanning. The trainer finds your player automatically, every match.

| Cheat | What it does |
|---|---|
| **Fast Construction** | Planet modules and structures build about 1000× faster. |
| **Fast Research** | Research finishes about 1000× faster. |
| **Fast Upgrade** | Planet upgrades finish about 1000× faster. |
| **Fast Production** | Ships from your factories build about 1000× faster. |
| **Unlimited Ships** | Adds **+2000 fleet supply** and **+20 capital ship slots** to your limits. |

### Custom ship limits (number boxes)

If you want a specific amount instead of the Unlimited Ships preset, use the two number boxes:

| Box | Range | Effect |
|---|---|---|
| **Extra fleet supply** | 0 – 100,000 | Added on top of your normal max fleet supply. |
| **Extra capital ship slots** | 0 – 100 | Added on top of your normal capital ship limit. |

- Any value above **0** is applied right away, with no ticking needed. Set it back to **0** to turn it off.
- Changing a number while you play updates the game live.
- While **Unlimited Ships** is ticked, it overrides the boxes. The two never stack.
- The boxes raise your **limit**. Your *available* ships are always "limit − ships you already
  have", so raising the limit by N gives you N more available.

### Status line

| Status | Meaning |
|---|---|
| `Attach to the game first.` | Not attached yet. |
| `Active on your player (N cheats on).` (green) | Working. |
| `Waiting: no match running.` (orange) | You are in the menus, or the match is still loading. It picks up the match by itself. |
| `Waiting: unexpected game version (v1.98 expected).` | The game exe is a different version. Nothing is written. See [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md#updating-for-a-new-game-version). |
| `Game code pattern not found ...` | Same as above: an unsupported game version. |

### Good to know

- **Turning off:** unticking a cheat, using **Turn all off**, or closing the trainer puts your
  original values back.
- **New match or loaded save:** detected automatically. You don't need to re-attach.
- **Items already in a queue** may keep the build time they were given when queued. Anything you
  queue *after* ticking the box is fast.
- **New ship limits** show once the game recalculates them, usually within a few seconds or when
  you build or research something.
- **Research bonuses:** if you finish a research that changes the same bonus, the trainer notices
  and keeps the cheat applied on top of the new value.

---

## Ship hull / shield

The **Ship hull / shield** box on the right of the Cheats tab sets a ship's current hull or shield
to the number you type, like Wand's "Set Highlighted Ship Hull / Shield".

| Control | What it does |
|---|---|
| **Ship hull value** + **Apply** | Sets the hull of the target ship(s) to this number. |
| **Ship shield value** + **Apply** | Sets the shield of the target ship(s) to this number. |

**Which ship is changed?**
1. The ship **under your mouse** in the game, the one the game highlights. This is the normal way:
   hover over a ship in the game and press the hotkey.
2. If no ship is under the mouse, **all ships you have selected**. This is what happens when you
   click **Apply** in the trainer window.

It works on any ship (frigates, capital ships, titans, starbases, fighters and mines), yours or the
enemy's. Planets and other objects are never changed.

Ideas:
- Give your own capital ship a huge hull, for example 100,000, to make it very hard to kill.
- Set an enemy ship's hull to **1** so that the next hit destroys it.

The box also shows a live readout: the ship under your mouse with its current hull and shield, and
how many ships are selected. If "Under mouse" shows a ship, the hotkey will hit that ship.

Notes:
- It's a **one-time set**, not a freeze. The ship can still take damage or regenerate afterwards.
- A value above the ship's normal maximum works, but the game may pull it back down as the ship regenerates.
- The game can keep remembering the last hovered ship after your mouse leaves the game window.
  Check the "Under mouse" line before clicking Apply in the trainer.

---

## Hotkeys

The trainer registers these system-wide while it is running, so they work while the game window is
focused. They are the same keys Wand uses.

| Hotkey | Action |
|---|---|
| **Alt+Q** | Set hull of the ship under the mouse (or the selected ships) |
| **Alt+W** | Set shield of the ship under the mouse (or the selected ships) |
| **Alt+3** / **Alt+4** | Ship hull value up / down by 1,000 |
| **Alt+1** / **Alt+2** | Ship shield value up / down by 1,000 |

If another program already uses one of these key combinations, that hotkey won't work.
The buttons in the trainer still do.

---

## Resources tab

This is the original scan-based part of the trainer, the same idea as Cheat Engine's value scan.
Use it for credits, metal and crystal.

| Row | Default "+N" button |
|---|---|
| Credits, Metal, Crystal | +10k |

How to use a row:

1. Type the number shown on **your HUD** (for example, Credits 3000) and click **First Scan**.
2. Let the value change in the game (spend or earn some), type the new HUD number and click **Next Scan**.
3. Repeat until the status shows only a few addresses (ideally 1–5; at most 25 can be written).
4. Type a **New value** and click **Set**, use the **+N** button, or tick **Freeze** to lock it.

Tips:
- If a scan finds nothing, change that row's **Type** (Float / Int32 / Double) and do a First Scan again.
- Small numbers (0 or 1) are too common to scan. Wait until the value is 2 or more.
- Addresses change with every new or loaded game, so scan again each match.

---


## Does it affect the AI?

**No.** Each player in a match (you, every AI, and the neutral pirate or minor-faction players)
has its own player object in the game's memory. The Cheats tab writes **only** to the one the game
marks as the local human player. The AI's own build speed, research speed and ship limits stay
normal.

The one exception is on purpose: the **ship hull / shield** tool changes whatever ship you point at,
including enemy ships. That is how you can set an enemy's hull to 1. It never changes anything you
didn't point at or select.

The game also has a built-in developer switch called "no slot restrictions". The trainer
deliberately does **not** use it, because it would remove ship limits for every player, the AI
included.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| **Attach failed** | Run the trainer as administrator. |
| **Game not in the list** | Start the game first, then click **Refresh**. |
| **Status stays "Waiting: no match running"** in a match | Click **Attach** again. If it persists, check the player count in [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md#troubleshooting-the-pointer-chain). |
| **A cheat seems to do nothing** | Start a *new* item after ticking it; already-queued items may keep their old time. |
| **Ship limit didn't change** | Wait a few seconds, or build or research something so the game recalculates it. |
| **Hull/shield: "No ship under the mouse and no ship selected"** | Hover over a ship in the game and use Alt+Q / Alt+W, or select ships first and click Apply. |
| **Hull/shield hotkey does nothing** | Another program may own that key combination. Use the Apply buttons instead. |
| **"Ship tools are not available for this game version"** | The game exe isn't v1.98; the hull/shield tools are switched off and nothing is written. |
| **Build fails: "file is being used by another process"** | Close the running trainer, then build again. |
| **"Unexpected game version"** | The game exe isn't v1.98. See [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md#updating-for-a-new-game-version). |

---

## Safety notes

- **Save first:** save your game before using a cheat for the first time.
- **Version check:** the Cheats tab checks that it is talking to the exact v1.98 game before
  writing anything. On any other version it writes nothing.
- **Restoring:** closing the trainer restores the values the Cheats tab changed.
- **Single-player only:** don't use it online.

---

## For developers

How the cheats work (pointer chain, offsets, byte patterns), how they were found, and how to add
a cheat or update for a new game version are all in **[REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md)**.
