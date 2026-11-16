// Sins of a Solar Empire: Rebellion - single-player resource trainer.
// Finds YOUR credits / metal / crystal / fleet supply / capital ships by the values
// shown on your HUD, so only the human player's values are changed (AI values are never touched).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;

static class Native
{
    public const uint PROCESS_ACCESS = 0x0010 | 0x0020 | 0x0008 | 0x0400; // VM_READ | VM_WRITE | VM_OPERATION | QUERY_INFORMATION
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr written);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    public struct MBI
    {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State, Protect, Type;
    }

    // Module enumeration that also sees 32-bit modules of a WOW64 game from this 64-bit trainer.
    public const uint LIST_MODULES_ALL = 0x03;
    [DllImport("psapi.dll", SetLastError = true)] public static extern bool EnumProcessModulesEx(IntPtr h, [Out] IntPtr[] mods, int cb, out int needed, uint filter);
    [DllImport("psapi.dll", CharSet = CharSet.Unicode)] public static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, System.Text.StringBuilder sb, int size);
    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO { public IntPtr lpBaseOfDll; public uint SizeOfImage; public IntPtr EntryPoint; }
    [DllImport("psapi.dll", SetLastError = true)] public static extern bool GetModuleInformation(IntPtr h, IntPtr mod, out MODULEINFO mi, int cb);
}

enum ValType { Float, Int32, Double }

class Mem
{
    public IntPtr Handle = IntPtr.Zero;
    public Process Proc;
    public const int MAX_RESULTS = 20000000;

    public bool Attach(Process p)
    {
        Detach();
        Handle = Native.OpenProcess(Native.PROCESS_ACCESS, false, p.Id);
        if (Handle == IntPtr.Zero) return false;
        Proc = p;
        return true;
    }
    public void Detach()
    {
        if (Handle != IntPtr.Zero) Native.CloseHandle(Handle);
        Handle = IntPtr.Zero; Proc = null;
    }
    public bool Alive { get { try { return Proc != null && !Proc.HasExited; } catch { return false; } } }

    public static int Size(ValType t) { return t == ValType.Double ? 8 : 4; }

    public static double Decode(byte[] b, int off, ValType t)
    {
        switch (t)
        {
            case ValType.Float: return BitConverter.ToSingle(b, off);
            case ValType.Int32: return BitConverter.ToInt32(b, off);
            default: return BitConverter.ToDouble(b, off);
        }
    }
    public static byte[] Encode(double v, ValType t)
    {
        switch (t)
        {
            case ValType.Float: return BitConverter.GetBytes((float)v);
            case ValType.Int32: return BitConverter.GetBytes((int)Math.Round(v));
            default: return BitConverter.GetBytes(v);
        }
    }
    // HUD shows whole numbers; resources can have a fraction, so allow +/- 1.
    // exact=true for small counters (fleet supply, capital ships).
    public static bool Matches(double v, double target, ValType t, bool exact)
    {
        if (double.IsNaN(v) || double.IsInfinity(v)) return false;
        if (t == ValType.Int32) return v == target;
        return Math.Abs(v - target) < (exact ? 0.01 : 1.0);
    }

    public bool Read(long addr, int size, out byte[] buf)
    {
        buf = new byte[size];
        IntPtr read;
        return Native.ReadProcessMemory(Handle, new IntPtr(addr), buf, new IntPtr(size), out read) && read.ToInt64() == size;
    }
    public bool Write(long addr, byte[] data)
    {
        IntPtr w;
        return Native.WriteProcessMemory(Handle, new IntPtr(addr), data, new IntPtr(data.Length), out w);
    }
    public bool ReadValue(long addr, ValType t, out double v)
    {
        byte[] b; v = 0;
        if (!Read(addr, Size(t), out b)) return false;
        v = Decode(b, 0, t); return true;
    }

    // The game is a 32-bit process, so its pointers are 4 bytes.
    public bool ReadU32(long addr, out long v)
    {
        byte[] b; v = 0;
        if (!Read(addr, 4, out b)) return false;
        v = BitConverter.ToUInt32(b, 0); return true;
    }
    public bool ReadF32(long addr, out float v)
    {
        byte[] b; v = 0;
        if (!Read(addr, 4, out b)) return false;
        v = BitConverter.ToSingle(b, 0); return true;
    }
    public bool WriteF32(long addr, float v) { return Write(addr, BitConverter.GetBytes(v)); }

    // Base address and size of the game's main .exe module (works for a 32-bit game from this 64-bit trainer).
    public bool MainModule(out long baseAddr, out long size)
    {
        baseAddr = 0; size = 0;
        var mods = new IntPtr[1024];
        int needed;
        if (!Native.EnumProcessModulesEx(Handle, mods, mods.Length * IntPtr.Size, out needed, Native.LIST_MODULES_ALL)) return false;
        int n = Math.Min(mods.Length, needed / IntPtr.Size);
        string exeName = Proc.ProcessName + ".exe";
        for (int i = 0; i < n; i++)
        {
            var sb = new System.Text.StringBuilder(1024);
            Native.GetModuleFileNameExW(Handle, mods[i], sb, sb.Capacity);
            if (!sb.ToString().EndsWith(exeName, StringComparison.OrdinalIgnoreCase)) continue;
            Native.MODULEINFO mi;
            if (!Native.GetModuleInformation(Handle, mods[i], out mi, Marshal.SizeOf(typeof(Native.MODULEINFO)))) return false;
            baseAddr = mi.lpBaseOfDll.ToInt64(); size = mi.SizeOfImage;
            return true;
        }
        return false;
    }

    // Finds every match of an IDA-style byte pattern ("8B 0D ?? ?? ...") inside [start, start+len).
    public List<long> FindPattern(long start, int len, string pattern)
    {
        var res = new List<long>();
        string[] tok = pattern.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        var pat = new int[tok.Length];
        for (int i = 0; i < tok.Length; i++) pat[i] = tok[i] == "??" ? -1 : Convert.ToInt32(tok[i], 16);
        byte[] buf;
        if (!Read(start, len, out buf)) return res;
        for (int i = 0; i + pat.Length <= buf.Length; i++)
        {
            int j = 0;
            while (j < pat.Length && (pat[j] < 0 || buf[i + j] == pat[j])) j++;
            if (j == pat.Length) res.Add(start + i);
        }
        return res;
    }

    // Walks all writable committed memory, calling onChunk(baseAddress, buffer, bytesRead).
    void ForEachChunk(Func<long, byte[], int, bool> onChunk)
    {
        long addr = 0;
        long max = IntPtr.Size == 8 ? 0x7FFFFFFFFFFF : 0x7FFFFFFF;
        int mbiSize = Marshal.SizeOf(typeof(Native.MBI));
        const int CHUNK = 16 * 1024 * 1024;
        byte[] buf = new byte[CHUNK];
        while (addr < max)
        {
            Native.MBI mbi;
            if (Native.VirtualQueryEx(Handle, new IntPtr(addr), out mbi, new IntPtr(mbiSize)) == IntPtr.Zero) break;
            long baseA = mbi.BaseAddress.ToInt64();
            long rsize = mbi.RegionSize.ToInt64();
            if (rsize <= 0) break;
            bool writable = (mbi.Protect & (0x04 | 0x08 | 0x40 | 0x80)) != 0 && (mbi.Protect & 0x100) == 0;
            if (mbi.State == 0x1000 && writable)
            {
                for (long off = 0; off < rsize; off += CHUNK)
                {
                    int len = (int)Math.Min(CHUNK, rsize - off);
                    IntPtr read;
                    if (!Native.ReadProcessMemory(Handle, new IntPtr(baseA + off), buf, new IntPtr(len), out read)) continue;
                    if (!onChunk(baseA + off, buf, (int)read.ToInt64())) return;
                }
            }
            addr = baseA + rsize;
        }
    }

    // Full scan of all writable committed memory. keep==null => accept all matches.
    // Returns null if the value is too common (more than MAX_RESULTS hits).
    public List<long> Scan(double target, ValType t, bool exact, HashSet<long> keep)
    {
        var result = new List<long>();
        int sz = Size(t);
        long addr = 0;
        long max = IntPtr.Size == 8 ? 0x7FFFFFFFFFFF : 0x7FFFFFFF;
        int mbiSize = Marshal.SizeOf(typeof(Native.MBI));
        const int CHUNK = 16 * 1024 * 1024;
        byte[] buf = new byte[CHUNK];
        while (addr < max)
        {
            Native.MBI mbi;
            if (Native.VirtualQueryEx(Handle, new IntPtr(addr), out mbi, new IntPtr(mbiSize)) == IntPtr.Zero) break;
            long baseA = mbi.BaseAddress.ToInt64();
            long rsize = mbi.RegionSize.ToInt64();
            if (rsize <= 0) break;
            bool writable = (mbi.Protect & (0x04 | 0x08 | 0x40 | 0x80)) != 0 && (mbi.Protect & 0x100) == 0;
            if (mbi.State == 0x1000 && writable)
            {
                for (long off = 0; off < rsize; off += CHUNK)
                {
                    int len = (int)Math.Min(CHUNK, rsize - off);
                    IntPtr read;
                    if (!Native.ReadProcessMemory(Handle, new IntPtr(baseA + off), buf, new IntPtr(len), out read)) continue;
                    int n = (int)read.ToInt64();
                    for (int i = 0; i + sz <= n; i += 4)
                    {
                        if (Matches(Decode(buf, i, t), target, t, exact))
                        {
                            long a = baseA + off + i;
                            if (keep == null || keep.Contains(a))
                            {
                                result.Add(a);
                                if (result.Count > MAX_RESULTS) return null;
                            }
                        }
                    }
                }
            }
            addr = baseA + rsize;
        }
        return result;
    }
}

// ===================== Auto cheats (no scanning) =====================
// Found by reverse engineering "Sins of a Solar Empire Rebellion.exe" v1.98 (32-bit) with REA + Ghidra.
// Every cheat writes ONLY to the local (human) player's research modifier table, so AI players are untouched.
//
//   Game      = [global]                      global found by byte pattern (address differs every run - ASLR)
//   L         = [Game + 0x570C]               player list
//   index     = [L + 0x2668]                  local player index   (count at L+0x2660)
//   player    = [[L + 0x2664] + index*4]      Player object (vtable checked below)
//   P         = player + 0x18                 player data (what Player vfunc 0x20C returns)
//   P + 0x410 + type*4                        float research modifiers, used by the game as  time / (1 + value)
static class SinsOffsets
{
    // mov ecx,[Game] ; mov eax,[ecx+0x570C] ; mov eax,[eax+0x2668]   (unique in v1.98)
    public const string PAT_GAME = "8B 0D ?? ?? ?? ?? 8B 81 0C 57 00 00 8B 80 68 26 00 00";
    // mov ecx,[Game] ; mov ecx,[ecx+0x570C]   (8 hits in v1.98, all must agree)
    public const string PAT_GAME_ALT = "8B 0D ?? ?? ?? ?? 8B 89 0C 57 00 00";
    public const int PLAYER_LIST = 0x570C, PLAYER_COUNT = 0x2660, PLAYER_ARRAY = 0x2664, LOCAL_INDEX = 0x2668;
    public const int PLAYER_DATA = 0x18;
    public const long PLAYER_VTABLE_RVA = 0x57C524;   // Iron::Player vtable, module-relative (v1.98)

    public const int MOD_CAPITAL_SHIP_MAX_SLOTS = 0x494;      // type 0x21 CapitalShipMaxSlots (additive, floored)
    public const int MOD_PLANET_UPGRADE_RATE = 0x544;         // type 0x4D PlanetUpgradeBuildRateAdjustment
    public const int MOD_MODULE_BUILD_RATE = 0x560;           // type 0x54 ModuleBuildRateAdjustment
    public const int MOD_RESEARCH_RATE = 0x594;               // type 0x61 ResearchBuildRateAdjustment
    public const int MOD_SHIP_BUILD_RATE = 0x5B4;             // type 0x69 ShipBuildRateAdjustment
    public const int MOD_SHIP_MAX_SLOTS = 0x5BC;              // type 0x6B ShipMaxSlots = fleet supply (additive)
    // Second copy of the modifier block (same layout). Ship-slot recalculation turns [D+0x5BC] into the HUD max
    // (D+0x1D8) and [D+0x1B54] into the max the build check uses (D+0x1DC); capital: 0x494 -> D+0x258, 0x1A2C -> D+0x25C.
    public const int MOD_MIRROR = 0x1598;

    // ---- Ships: selection / mouse-over and hull/shield ----
    // Static init of the selection globals:  mov [Sel],eax ; push .. ; mov [eax],eax ; mov eax,[Sel] ; mov [eax+4],eax ; mov [Hover],0
    public const string PAT_SEL = "A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 00 A1 ?? ?? ?? ?? 89 40 04 C7 05 ?? ?? ?? ?? 00 00 00 00";
    public const int PAT_SEL_LIST = 1, PAT_SEL_HOVER = 22;
    // Debug "all selected entities" loop:  mov eax,[Sel] ; push ebx/esi/edi ; mov esi,[eax] ; ...
    public const string PAT_SEL_ALT = "A1 ?? ?? ?? ?? 53 56 57 8B 30 8B F9 3B F0 74 1E";
    // [Sel] = list head node (circular: node = {next, prev, Entity*}),  [Sel+4] = selected count,  [Sel+8] = entity under cursor
    public const int SEL_COUNT = 4, SEL_HOVER = 8, NODE_ENTITY = 8;
    // Hull / shield block inside each entity class (what Entity vfunc +0xBC returns); hull = block+0xC, shield = block+0x10 (floats)
    public const int HULL = 0xC, SHIELD = 0x10;
    public static readonly ShipClass[] SHIP_CLASSES =
    {
        new ShipClass("Frigate",      0x582764, 0x580),
        new ShipClass("Capital ship", 0x583E70, 0x5C0),
        new ShipClass("Titan",        0x5795D8, 0x574),
        new ShipClass("Starbase",     0x57A794, 0x638),
        new ShipClass("Fighter",      0x578FC8, 0x400),
        new ShipClass("Space mine",   0x57B188, 0x3C0),
    };
}

class ShipClass
{
    public readonly string Name; public readonly long VtableRva; public readonly int DamageBlock;
    public ShipClass(string n, long vt, int blk) { Name = n; VtableRva = vt; DamageBlock = blk; }
}

class ShipTarget
{
    public long Entity; public ShipClass Class;
    public long HullAddr { get { return Entity + Class.DamageBlock + SinsOffsets.HULL; } }
    public long ShieldAddr { get { return Entity + Class.DamageBlock + SinsOffsets.SHIELD; } }
}

class CheatField
{
    public int Offset;
    public bool Additive;      // true: original + Value, false: set to Value
    public float Value;
    public Func<float> ValueFn;   // when set, overrides Value (number boxes / presets)
    public float Current { get { return ValueFn != null ? ValueFn() : Value; } }
    public bool HasOrig;
    public float Orig, LastWritten;
}

class Cheat
{
    public string Name, Help;
    public CheatField[] Fields;
    public CheckBox Chk;
    public Label Lbl;
    public bool Custom;          // driven by a number box instead of a checkbox
    public Func<bool> IsOn;      // when set, decides if the cheat is active (used by the number boxes)
    public bool Enabled { get { return IsOn != null ? IsOn() : (Chk != null && Chk.Checked); } }
}

class GameCheats
{
    readonly Mem mem;
    public long ModBase, ModSize, GameGlobal;
    long lastPlayerData;
    public readonly List<Cheat> Cheats = new List<Cheat>();

    public GameCheats(Mem m) { mem = m; }

    static CheatField Set(int off, float v) { return new CheatField { Offset = off, Value = v }; }
    static CheatField Add(int off, float v) { return new CheatField { Offset = off, Value = v, Additive = true }; }

    public void Define()
    {
        // A rate value of 999 makes the timer 1000x faster (the game divides the time by 1 + value).
        Cheats.Add(new Cheat { Name = "Fast Construction", Help = "planet modules / structures build ~instantly",
            Fields = new[] { Set(SinsOffsets.MOD_MODULE_BUILD_RATE, 999f) } });
        Cheats.Add(new Cheat { Name = "Fast Research", Help = "research finishes ~instantly",
            Fields = new[] { Set(SinsOffsets.MOD_RESEARCH_RATE, 999f) } });
        Cheats.Add(new Cheat { Name = "Fast Upgrade", Help = "planet upgrades finish ~instantly",
            Fields = new[] { Set(SinsOffsets.MOD_PLANET_UPGRADE_RATE, 999f) } });
        Cheats.Add(new Cheat { Name = "Fast Production", Help = "ships from factories build ~instantly",
            Fields = new[] { Set(SinsOffsets.MOD_SHIP_BUILD_RATE, 999f) } });
        // "Unlimited Ships" is a preset (+2000 / +20) for the two ship-limit entries below, so the
        // checkbox and the number boxes never stack on the same game value.
        Cheats.Add(new Cheat { Name = "Unlimited Ships", Help = "+2000 fleet supply, +20 capital ship slots",
            Fields = new CheatField[0] });
        // Ship limit entries: preset when "Unlimited Ships" is ticked, otherwise the number boxes.
        // Each limit lives in two modifier blocks: the first feeds the HUD, the mirror (+MOD_MIRROR) feeds
        // the build checks (CanRequestShip), so both must be raised or the game says "Insufficient Fleet Capacity".
        Cheats.Add(new Cheat { Name = "Extra fleet supply", Custom = true,
            Fields = new[] { Add(SinsOffsets.MOD_SHIP_MAX_SLOTS, 0f), Add(SinsOffsets.MOD_SHIP_MAX_SLOTS + SinsOffsets.MOD_MIRROR, 0f) } });
        Cheats.Add(new Cheat { Name = "Extra capital ship slots", Custom = true,
            Fields = new[] { Add(SinsOffsets.MOD_CAPITAL_SHIP_MAX_SLOTS, 0f), Add(SinsOffsets.MOD_CAPITAL_SHIP_MAX_SLOTS + SinsOffsets.MOD_MIRROR, 0f) } });
    }

    public Cheat Find(string name) { return Cheats.Find(c => c.Name == name); }

    public void Reset()
    {
        ModBase = ModSize = GameGlobal = SelGlobal = 0;
        lastPlayerData = 0;
        foreach (var c in Cheats) foreach (var f in c.Fields) f.HasOrig = false;
    }

    // Locates the game module and the Game global. Returns an error text, or null on success.
    public string Init()
    {
        Reset();
        long b, s;
        if (!mem.MainModule(out b, out s)) return "Could not read the game module (try running as Administrator).";
        ModBase = b; ModSize = s;
        // .text section from the in-memory PE header
        byte[] hdr;
        if (!mem.Read(b, 0x1000, out hdr)) return "Could not read the game's PE header.";
        int pe = BitConverter.ToInt32(hdr, 0x3C);
        int nsec = BitConverter.ToUInt16(hdr, pe + 6), optSz = BitConverter.ToUInt16(hdr, pe + 20);
        long textStart = 0; int textLen = 0;
        for (int i = 0; i < nsec; i++)
        {
            int sh = pe + 24 + optSz + i * 40;
            string name = System.Text.Encoding.ASCII.GetString(hdr, sh, 8).TrimEnd('\0');
            if (name == ".text") { textLen = BitConverter.ToInt32(hdr, sh + 8); textStart = b + BitConverter.ToInt32(hdr, sh + 12); break; }
        }
        if (textLen <= 0) return "Game .text section not found.";

        var hits = mem.FindPattern(textStart, textLen, SinsOffsets.PAT_GAME);
        if (hits.Count != 1) hits = mem.FindPattern(textStart, textLen, SinsOffsets.PAT_GAME_ALT);
        if (hits.Count == 0) return "Game code pattern not found - this game version is not supported.";
        long g = -1;
        foreach (var h in hits)
        {
            long v;
            if (!mem.ReadU32(h + 2, out v)) return "Could not read the game code.";
            if (g >= 0 && v != g) return "Game code pattern is ambiguous - this game version is not supported.";
            g = v;
        }
        GameGlobal = g;

        // Selection / mouse-over globals (for the ship hull/shield tools). Optional: cheats still work without them.
        SelGlobal = 0;
        var selHits = mem.FindPattern(textStart, textLen, SinsOffsets.PAT_SEL);
        if (selHits.Count == 1)
        {
            long list, hover;
            if (mem.ReadU32(selHits[0] + SinsOffsets.PAT_SEL_LIST, out list) && mem.ReadU32(selHits[0] + SinsOffsets.PAT_SEL_HOVER, out hover)
                && hover == list + SinsOffsets.SEL_HOVER)
            {
                var alt = mem.FindPattern(textStart, textLen, SinsOffsets.PAT_SEL_ALT);
                long a2;
                if (alt.Count == 1 && mem.ReadU32(alt[0] + 1, out a2) && a2 == list) SelGlobal = list;
            }
        }
        return null;
    }

    // ===================== Ships (hull / shield) =====================
    public long SelGlobal;   // address of the selection list global; +4 count, +8 entity under cursor

    ShipTarget AsShip(long entity)
    {
        long vt;
        if (entity == 0 || !mem.ReadU32(entity, out vt)) return null;
        foreach (var c in SinsOffsets.SHIP_CLASSES)
            if (vt == ModBase + c.VtableRva) return new ShipTarget { Entity = entity, Class = c };
        return null;   // planet, asteroid, unknown object: never written
    }

    public ShipTarget Hovered()
    {
        long e;
        if (SelGlobal == 0 || !mem.ReadU32(SelGlobal + SinsOffsets.SEL_HOVER, out e)) return null;
        return AsShip(e);
    }

    public List<ShipTarget> Selected()
    {
        var res = new List<ShipTarget>();
        long head, count, node, ent;
        if (SelGlobal == 0 || !mem.ReadU32(SelGlobal, out head) || head == 0) return res;
        if (!mem.ReadU32(SelGlobal + SinsOffsets.SEL_COUNT, out count) || count <= 0 || count > 2000) return res;
        if (!mem.ReadU32(head, out node)) return res;
        for (int i = 0; node != 0 && node != head && i < count; i++)
        {
            if (!mem.ReadU32(node + SinsOffsets.NODE_ENTITY, out ent)) break;
            var s = AsShip(ent);
            if (s != null) res.Add(s);
            if (!mem.ReadU32(node, out node)) break;
        }
        return res;
    }

    // The ship under the mouse if there is one, otherwise every selected ship.
    public List<ShipTarget> Targets(out string what)
    {
        var h = Hovered();
        if (h != null) { what = "highlighted " + h.Class.Name.ToLower(); return new List<ShipTarget> { h }; }
        var sel = Selected();
        what = sel.Count == 0 ? "" : sel.Count + " selected ship" + (sel.Count == 1 ? "" : "s");
        return sel;
    }

    public string Describe(ShipTarget s)
    {
        float hull, shield;
        mem.ReadF32(s.HullAddr, out hull); mem.ReadF32(s.ShieldAddr, out shield);
        return s.Class.Name + "  hull " + hull.ToString("N0") + "  shield " + shield.ToString("N0");
    }

    // Address of the local player's data block (player + 0x18), or 0 if not in a match / not valid.
    public long LocalPlayerData(out string why)
    {
        why = null;
        long game, list, count, index, arr, player, vt;
        if (GameGlobal == 0) { why = "not detected"; return 0; }
        if (!mem.ReadU32(GameGlobal, out game) || game == 0) { why = "game not ready"; return 0; }
        if (!mem.ReadU32(game + SinsOffsets.PLAYER_LIST, out list) || list == 0) { why = "no match running"; return 0; }
        if (!mem.ReadU32(list + SinsOffsets.PLAYER_COUNT, out count) || count <= 0 || count > 64) { why = "no match running"; return 0; }   // count includes neutral players; SotP v0.91 has 27
        if (!mem.ReadU32(list + SinsOffsets.LOCAL_INDEX, out index) || index >= count) { why = "no local player"; return 0; }
        if (!mem.ReadU32(list + SinsOffsets.PLAYER_ARRAY, out arr) || arr == 0) { why = "no match running"; return 0; }
        if (!mem.ReadU32(arr + index * 4, out player) || player == 0) { why = "no local player"; return 0; }
        // Safety: only touch memory that really is an Iron::Player object of this exact game build.
        if (!mem.ReadU32(player, out vt) || vt != ModBase + SinsOffsets.PLAYER_VTABLE_RVA) { why = "unexpected game version (v1.98 expected)"; return 0; }
        return player + SinsOffsets.PLAYER_DATA;
    }

    // Called 4x per second. Applies enabled cheats, restores disabled ones. Returns a status text.
    public string Tick()
    {
        string why;
        long p = LocalPlayerData(out why);
        if (p == 0) { lastPlayerData = 0; return "Waiting: " + why + "."; }
        if (p != lastPlayerData)
        {
            // New match / loaded save: forget values remembered from the old player object.
            foreach (var c in Cheats) foreach (var f in c.Fields) f.HasOrig = false;
            lastPlayerData = p;
        }
        int on = 0;
        bool customOn = false;
        foreach (var c in Cheats)
        {
            bool enabled = c.Enabled;
            foreach (var f in c.Fields)
            {
                long a = p + f.Offset;
                float cur;
                if (!mem.ReadF32(a, out cur) || float.IsNaN(cur) || float.IsInfinity(cur)) continue;
                if (enabled)
                {
                    // Remember the game's own value; if the game recalculated it (e.g. research done), take the new one.
                    if (!f.HasOrig || cur != f.LastWritten) { f.Orig = cur; f.HasOrig = true; }
                    float want = f.Additive ? f.Orig + f.Current : f.Current;
                    if (cur != want) mem.WriteF32(a, want);
                    f.LastWritten = want;
                }
                else if (f.HasOrig)
                {
                    if (cur == f.LastWritten) mem.WriteF32(a, f.Orig);   // put the game's value back
                    f.HasOrig = false;
                }
            }
            if (enabled && !c.Custom) on++;
            if (enabled && c.Custom) customOn = true;
        }
        var unl = Find("Unlimited Ships");
        if (customOn && (unl == null || !unl.Enabled)) on++;   // custom ship limits count as one cheat
        return "Active on your player (" + on + " cheat" + (on == 1 ? "" : "s") + " on).";
    }

    // Restores every field (used when the trainer closes or detaches).
    public void RestoreAll()
    {
        string why;
        long p = LocalPlayerData(out why);
        foreach (var c in Cheats) foreach (var f in c.Fields)
        {
            if (p != 0 && p == lastPlayerData && f.HasOrig)
            {
                float cur;
                if (mem.ReadF32(p + f.Offset, out cur) && cur == f.LastWritten) mem.WriteF32(p + f.Offset, f.Orig);
            }
            f.HasOrig = false;
        }
    }
}

class ResourceRow
{
    public string Name;
    public bool Exact;
    public double AddAmount;
    public List<long> Candidates = new List<long>();
    public ComboBox CmbType;
    public TextBox TxtSeen, TxtNew;
    public Button BtnFirst, BtnNext, BtnSet, BtnAdd, BtnReset;
    public CheckBox ChkFreeze;
    public Label LblStatus;
    public double FreezeValue;
    public ValType Type { get { return (ValType)CmbType.SelectedIndex; } }
}

class TrainerForm : Form
{
    Mem mem = new Mem();
    ComboBox cmbProc;
    Label lblAttach;
    List<ResourceRow> rows = new List<ResourceRow>();
    Timer timer;
    const int MAX_WRITE = 25;
    const int W = 1010, H = 760;
    TabPage resPage;
    GameCheats cheats;
    Label cheatStatus;

    public TrainerForm()
    {
        Text = "Sins Rebellion Trainer (single-player)";
        Font = new Font("Segoe UI", 9f);
        ClientSize = new Size(W, H);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;

        var lp = new Label { Text = "Game process:", Location = new Point(12, 15), AutoSize = true };
        cmbProc = new ComboBox { Location = new Point(110, 11), Width = 330, DropDownStyle = ComboBoxStyle.DropDownList };
        var btnRefresh = new Button { Text = "Refresh", Location = new Point(448, 10), Width = 75 };
        var btnAttach = new Button { Text = "Attach", Location = new Point(528, 10), Width = 75 };
        lblAttach = new Label { Text = "Not attached", Location = new Point(612, 15), AutoSize = true, ForeColor = Color.DarkRed };
        btnRefresh.Click += delegate { RefreshProcs(); };
        btnAttach.Click += delegate { DoAttach(); };
        Controls.AddRange(new Control[] { lp, cmbProc, btnRefresh, btnAttach, lblAttach });

        var tabs = new TabControl { Location = new Point(4, 44), Size = new Size(W - 8, H - 48) };
        var cheatPage = new TabPage("Cheats");
        resPage = new TabPage("Resources");
        tabs.TabPages.Add(cheatPage);
        tabs.TabPages.Add(resPage);
        Controls.Add(tabs);
        int pageH = tabs.Height - 30;

        cheats = new GameCheats(mem);
        cheats.Define();
        BuildCheatsTab(cheatPage, pageH);

        resPage.Controls.Add(new Label
        {
            Text = "If a scan finds nothing, change that row's Type (Float / Int32 / Double) and do a First Scan again.",
            Location = new Point(8, 8), AutoSize = true, ForeColor = Color.DimGray
        });

        string[] hdr = { "Resource", "Type", "Value on HUD", "", "", "Status", "New value", "", "", "" };
        int[] xs = { 8, 151, 236, 321, 406, 491, 696, 781, 836, 901 };
        for (int i = 0; i < hdr.Length; i++)
            resPage.Controls.Add(new Label { Text = hdr[i], Location = new Point(xs[i], 36), AutoSize = true, Font = new Font(Font, FontStyle.Bold) });

        int y = 60;
        AddRow("Credits", y, false, 10000, "999999"); y += 36;
        AddRow("Metal", y, false, 10000, "999999"); y += 36;
        AddRow("Crystal", y, false, 10000, "999999"); y += 36;

        resPage.Controls.Add(new Label
        {
            Location = new Point(8, y + 4), Size = new Size(W - 40, pageH - y - 4), ForeColor = Color.DimGray,
            Text =
"HOW TO USE (single-player / vs AI only):\r\n" +
"1. Start a game, then Alt-Tab here, pick the game process and click Attach.\r\n" +
"2. Type the number you see on YOUR HUD (e.g. Credits 3000) and click First Scan.\r\n" +
"3. Go back to the game and let it change (unpause, buy something). Type the new HUD number and click Next Scan.\r\n" +
"4. Repeat until Status shows only a few addresses (ideally 1-5). Then type a New value and click Set / +N, and tick Freeze to lock it.\r\n" +
"5. Addresses change every new or loaded game, so scan again each match.\r\n" +
"Tip: pausing the game while scanning is fine as long as the HUD number matches what you type. Run as Administrator if Attach fails."
        });

        timer = new Timer { Interval = 250 };
        timer.Tick += delegate { Tick(); };
        timer.Start();

        RefreshProcs();
    }

    void AddRow(string name, int y, bool exact, double addAmount, string defNew)
    {
        var r = new ResourceRow { Name = name, Exact = exact, AddAmount = addAmount };
        resPage.Controls.Add(new Label { Text = name, Location = new Point(8, y + 4), AutoSize = true });
        r.CmbType = new ComboBox { Location = new Point(151, y), Width = 75, DropDownStyle = ComboBoxStyle.DropDownList };
        r.CmbType.Items.AddRange(new object[] { "Float", "Int32", "Double" });
        r.CmbType.SelectedIndex = 0;
        r.CmbType.SelectedIndexChanged += delegate { ResetRow(r); };
        r.TxtSeen = new TextBox { Location = new Point(236, y), Width = 80 };
        r.BtnFirst = new Button { Text = "First Scan", Location = new Point(321, y - 1), Width = 80 };
        r.BtnNext = new Button { Text = "Next Scan", Location = new Point(406, y - 1), Width = 80, Enabled = false };
        r.LblStatus = new Label { Text = "-", Location = new Point(491, y + 4), Size = new Size(200, 20) };
        r.TxtNew = new TextBox { Location = new Point(696, y), Width = 80, Text = defNew };
        r.BtnSet = new Button { Text = "Set", Location = new Point(781, y - 1), Width = 50, Enabled = false };
        string addTxt = (addAmount > 0 ? "+" : "") + (Math.Abs(addAmount) >= 1000 ? (addAmount / 1000) + "k" : addAmount.ToString());
        r.BtnAdd = new Button { Text = addTxt, Location = new Point(836, y - 1), Width = 60, Enabled = false };
        r.ChkFreeze = new CheckBox { Text = "Freeze", Location = new Point(901, y + 2), AutoSize = true, Enabled = false };
        r.BtnReset = new Button { Text = "x", Location = new Point(966, y - 1), Width = 22 };
        r.BtnFirst.Click += delegate { DoScan(r, true); };
        r.BtnNext.Click += delegate { DoScan(r, false); };
        r.BtnSet.Click += delegate { DoSet(r, null); };
        r.BtnAdd.Click += delegate { DoSet(r, r.AddAmount); };
        r.BtnReset.Click += delegate { ResetRow(r); };
        r.ChkFreeze.CheckedChanged += delegate
        {
            if (r.ChkFreeze.Checked)
            {
                double v;
                if (!TryNum(r.TxtNew.Text, out v)) { r.ChkFreeze.Checked = false; return; }
                if (!ConfirmWriteCount(r)) { r.ChkFreeze.Checked = false; return; }
                r.FreezeValue = v;
            }
        };
        resPage.Controls.AddRange(new Control[] { r.CmbType, r.TxtSeen, r.BtnFirst, r.BtnNext, r.LblStatus, r.TxtNew, r.BtnSet, r.BtnAdd, r.ChkFreeze, r.BtnReset });
        rows.Add(r);
    }

    // ===================== Cheats tab =====================
    void BuildCheatsTab(TabPage p, int pageH)
    {
        p.Controls.Add(new Label
        {
            Text = "Toggle a cheat ON and it is applied to YOUR player only (AI players are never touched). No scanning needed.",
            Location = new Point(8, 10), AutoSize = true, ForeColor = Color.DimGray
        });
        cheatStatus = new Label { Text = "Attach to the game first.", Location = new Point(8, 34), AutoSize = true, Font = new Font(Font, FontStyle.Bold), ForeColor = Color.DarkRed };
        p.Controls.Add(cheatStatus);

        int y = 70;
        foreach (var c in cheats.Cheats)
        {
            if (c.Custom) continue;
            var cc = c;
            c.Chk = new CheckBox { Text = c.Name, Location = new Point(16, y), Width = 200, Font = new Font(Font.FontFamily, 11f, FontStyle.Bold) };
            c.Lbl = new Label { Text = c.Help, Location = new Point(230, y + 4), AutoSize = true, ForeColor = Color.DimGray };
            c.Chk.CheckedChanged += delegate
            {
                if (cc.Chk.Checked && (mem.Handle == IntPtr.Zero || cheats.GameGlobal == 0))
                {
                    MessageBox.Show("Attach to the game first (and start or load a match).");
                    cc.Chk.Checked = false;
                    return;
                }
                cheatStatus.Text = cheats.Tick();
            };
            p.Controls.Add(c.Chk); p.Controls.Add(c.Lbl);
            y += 40;
        }

        // ---- Custom ship limits (number boxes) ----
        var unlimited = cheats.Find("Unlimited Ships");
        var fleetCheat = cheats.Find("Extra fleet supply");
        var capCheat = cheats.Find("Extra capital ship slots");
        p.Controls.Add(new Label
        {
            Text = "Or set your own ship limits (used while Unlimited Ships is unticked; 0 = off):",
            Location = new Point(16, y + 4), AutoSize = true, Font = new Font(Font, FontStyle.Bold)
        });
        y += 30;
        p.Controls.Add(new Label { Text = "Extra fleet supply:", Location = new Point(32, y + 3), AutoSize = true });
        var numFleet = new NumericUpDown { Location = new Point(200, y), Width = 90, Minimum = 0, Maximum = 100000, Increment = 100 };
        p.Controls.Add(numFleet);
        p.Controls.Add(new Label { Text = "added on top of your normal max fleet supply", Location = new Point(300, y + 3), AutoSize = true, ForeColor = Color.DimGray });
        y += 32;
        p.Controls.Add(new Label { Text = "Extra capital ship slots:", Location = new Point(32, y + 3), AutoSize = true });
        var numCap = new NumericUpDown { Location = new Point(200, y), Width = 90, Minimum = 0, Maximum = 100, Increment = 1 };
        p.Controls.Add(numCap);
        p.Controls.Add(new Label { Text = "added on top of your normal capital ship limit", Location = new Point(300, y + 3), AutoSize = true, ForeColor = Color.DimGray });
        y += 36;

        fleetCheat.IsOn = () => unlimited.Chk.Checked || numFleet.Value > 0;
        capCheat.IsOn = () => unlimited.Chk.Checked || numCap.Value > 0;
        foreach (var f in fleetCheat.Fields) f.ValueFn = () => unlimited.Chk.Checked ? 2000f : (float)numFleet.Value;
        foreach (var f in capCheat.Fields) f.ValueFn = () => unlimited.Chk.Checked ? 20f : (float)numCap.Value;
        EventHandler onNum = delegate
        {
            if (mem.Handle != IntPtr.Zero && cheats.GameGlobal != 0) cheatStatus.Text = cheats.Tick();
        };
        numFleet.ValueChanged += onNum;
        numCap.ValueChanged += onNum;

        BuildShipBox(p);

        var bAllOff = new Button { Text = "Turn all off", Location = new Point(16, y + 6), Width = 120 };
        bAllOff.Click += delegate
        {
            foreach (var c in cheats.Cheats) if (c.Chk != null) c.Chk.Checked = false;
            numFleet.Value = 0; numCap.Value = 0;
        };
        p.Controls.Add(bAllOff);

        p.Controls.Add(new Label
        {
            Location = new Point(8, y + 50), Size = new Size(W - 40, pageH - y - 50), ForeColor = Color.DimGray,
            Text =
"HOW TO USE (single-player / vs AI only):\r\n" +
"1. Start or load a match, Alt-Tab here, pick the game process and click Attach.\r\n" +
"2. Tick the cheats you want. They stay applied while ticked, and are put back to normal when you untick them or close the trainer.\r\n" +
"3. A new match or a loaded save is picked up automatically.\r\n\r\n" +
"NOTES:\r\n" +
"- Fast Construction / Research / Upgrade / Production make the game's own build timers ~1000x faster for you.\r\n" +
"  Items that were already queued before you ticked the box may keep their old time - queue them again if needed.\r\n" +
"- Unlimited Ships raises YOUR fleet supply and capital ship limits. The new limit shows after the game recalculates it\r\n" +
"  (usually within a few seconds, or when you build/research something).\r\n" +
"- Made for Sins of a Solar Empire: Rebellion v1.98. Other versions are detected and refused, so nothing is written.\r\n" +
"- SAVE your game before trying the cheats for the first time."
        });
    }

    // ===================== Ship hull / shield (highlighted or selected ship) =====================
    NumericUpDown numHull, numShield;
    Label shipLive;
    const decimal SHIP_STEP = 1000;

    void BuildShipBox(TabPage p)
    {
        var g = new GroupBox { Text = "Ship hull / shield", Location = new Point(570, 60), Size = new Size(410, 236) };
        p.Controls.Add(g);
        g.Controls.Add(new Label
        {
            Text = "Works on the ship under your mouse. If there is none, it works on your selected ships.",
            Location = new Point(10, 20), Size = new Size(390, 32), ForeColor = Color.DimGray
        });

        g.Controls.Add(new Label { Text = "Ship hull value:", Location = new Point(10, 63), AutoSize = true });
        numHull = new NumericUpDown { Location = new Point(130, 60), Width = 100, Minimum = 1, Maximum = 10000000, Increment = SHIP_STEP, Value = 1, ThousandsSeparator = true };
        var bHull = new Button { Text = "Apply  (Alt+Q)", Location = new Point(240, 58), Width = 150 };
        bHull.Click += delegate { ApplyShip(true); };
        g.Controls.Add(numHull); g.Controls.Add(bHull);

        g.Controls.Add(new Label { Text = "Ship shield value:", Location = new Point(10, 98), AutoSize = true });
        numShield = new NumericUpDown { Location = new Point(130, 95), Width = 100, Minimum = 0, Maximum = 10000000, Increment = SHIP_STEP, Value = 1, ThousandsSeparator = true };
        var bShield = new Button { Text = "Apply  (Alt+W)", Location = new Point(240, 93), Width = 150 };
        bShield.Click += delegate { ApplyShip(false); };
        g.Controls.Add(numShield); g.Controls.Add(bShield);

        g.Controls.Add(new Label
        {
            Text = "Hotkeys (work while the game is focused):\r\n" +
                   "Alt+Q set hull   Alt+3 / Alt+4  hull value up / down\r\n" +
                   "Alt+W set shield   Alt+1 / Alt+2  shield value up / down",
            Location = new Point(10, 130), Size = new Size(390, 50), ForeColor = Color.DimGray
        });
        shipLive = new Label { Text = "-", Location = new Point(10, 180), Size = new Size(390, 48), Font = new Font(Font, FontStyle.Bold) };
        g.Controls.Add(shipLive);
    }

    void ApplyShip(bool hull)
    {
        if (mem.Handle == IntPtr.Zero || cheats.GameGlobal == 0) { shipLive.Text = "Attach to the game first."; return; }
        if (cheats.SelGlobal == 0) { shipLive.Text = "Ship tools are not available for this game version."; return; }
        string what;
        var targets = cheats.Targets(out what);
        if (targets.Count == 0) { shipLive.Text = "No ship under the mouse and no ship selected."; return; }
        float v = (float)(hull ? numHull.Value : numShield.Value);
        int ok = 0;
        foreach (var t in targets) if (mem.WriteF32(hull ? t.HullAddr : t.ShieldAddr, v)) ok++;
        shipLive.Text = (hull ? "Hull" : "Shield") + " set to " + v.ToString("N0") + " on " + what + (ok < targets.Count ? " (some writes failed)" : "") + ".";
        shipLiveHold = 8;   // keep this message visible for ~2 s
    }

    int shipLiveHold;
    void UpdateShipLive()
    {
        if (shipLive == null) return;
        if (shipLiveHold > 0) { shipLiveHold--; return; }
        if (mem.Handle == IntPtr.Zero || cheats.GameGlobal == 0 || cheats.SelGlobal == 0) return;
        var h = cheats.Hovered();
        var sel = cheats.Selected();
        string s = "Under mouse: " + (h == null ? "-" : cheats.Describe(h)) + "\r\n" + "Selected: " + sel.Count + " ship" + (sel.Count == 1 ? "" : "s");
        if (sel.Count == 1) s += "  (" + cheats.Describe(sel[0]) + ")";
        if (shipLive.Text != s) shipLive.Text = s;
    }

    // ---- global hotkeys (Alt+Q / Alt+W / Alt+1..4), like Wand ----
    [DllImport("user32.dll")] static extern bool RegisterHotKey(IntPtr hWnd, int id, uint mods, uint vk);
    [DllImport("user32.dll")] static extern bool UnregisterHotKey(IntPtr hWnd, int id);
    const uint MOD_ALT = 0x1, MOD_NOREPEAT = 0x4000;
    const int WM_HOTKEY = 0x0312;
    const int HK_HULL = 1, HK_SHIELD = 2, HK_HULL_UP = 3, HK_HULL_DOWN = 4, HK_SHIELD_UP = 5, HK_SHIELD_DOWN = 6;

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        RegisterHotKey(Handle, HK_HULL, MOD_ALT | MOD_NOREPEAT, (uint)Keys.Q);
        RegisterHotKey(Handle, HK_SHIELD, MOD_ALT | MOD_NOREPEAT, (uint)Keys.W);
        RegisterHotKey(Handle, HK_HULL_UP, MOD_ALT, (uint)Keys.D3);
        RegisterHotKey(Handle, HK_HULL_DOWN, MOD_ALT, (uint)Keys.D4);
        RegisterHotKey(Handle, HK_SHIELD_UP, MOD_ALT, (uint)Keys.D1);
        RegisterHotKey(Handle, HK_SHIELD_DOWN, MOD_ALT, (uint)Keys.D2);
    }

    protected override void OnHandleDestroyed(EventArgs e)
    {
        for (int id = HK_HULL; id <= HK_SHIELD_DOWN; id++) UnregisterHotKey(Handle, id);
        base.OnHandleDestroyed(e);
    }

    static void Step(NumericUpDown n, decimal d) { n.Value = Math.Max(n.Minimum, Math.Min(n.Maximum, n.Value + d)); }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WM_HOTKEY && numHull != null)
        {
            switch (m.WParam.ToInt32())
            {
                case HK_HULL: ApplyShip(true); break;
                case HK_SHIELD: ApplyShip(false); break;
                case HK_HULL_UP: Step(numHull, SHIP_STEP); break;
                case HK_HULL_DOWN: Step(numHull, -SHIP_STEP); break;
                case HK_SHIELD_UP: Step(numShield, SHIP_STEP); break;
                case HK_SHIELD_DOWN: Step(numShield, -SHIP_STEP); break;
            }
        }
        base.WndProc(ref m);
    }

    void RefreshProcs()
    {
        cmbProc.Items.Clear();
        foreach (var p in Process.GetProcesses().OrderBy(p => p.ProcessName))
        {
            if (p.ProcessName.IndexOf("Sins", StringComparison.OrdinalIgnoreCase) >= 0 ||
                p.ProcessName.IndexOf("Rebellion", StringComparison.OrdinalIgnoreCase) >= 0)
                cmbProc.Items.Add(new ProcItem(p));
        }
        if (cmbProc.Items.Count > 0) cmbProc.SelectedIndex = 0;
        else lblAttach.Text = "Game not running - start a game, then Refresh";
    }

    class ProcItem
    {
        public Process P;
        public ProcItem(Process p) { P = p; }
        public override string ToString() { return P.ProcessName + "  (PID " + P.Id + ")"; }
    }

    void DoAttach()
    {
        var item = cmbProc.SelectedItem as ProcItem;
        if (item == null) { MessageBox.Show("Start the game first, then click Refresh."); return; }
        if (mem.Attach(item.P))
        {
            lblAttach.Text = "Attached: " + item.P.ProcessName;
            lblAttach.ForeColor = Color.DarkGreen;
            foreach (var r in rows) ResetRow(r);
            string err = cheats.Init();
            cheatStatus.Text = err ?? cheats.Tick();
            cheatStatus.ForeColor = err == null ? Color.DarkGreen : Color.DarkRed;
        }
        else
        {
            lblAttach.Text = "Attach failed - run trainer as Administrator";
            lblAttach.ForeColor = Color.DarkRed;
        }
    }

    static bool TryNum(string s, out double v)
    {
        return double.TryParse(s.Replace(",", "").Trim(), System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out v);
    }

    void ResetRow(ResourceRow r)
    {
        r.Candidates.Clear();
        r.ChkFreeze.Checked = false;
        r.BtnNext.Enabled = r.BtnSet.Enabled = r.BtnAdd.Enabled = r.ChkFreeze.Enabled = false;
        r.LblStatus.Text = "-";
    }

    bool CheckAttached()
    {
        if (mem.Handle == IntPtr.Zero || !mem.Alive)
        {
            MessageBox.Show("Not attached to the game. Start a game, click Refresh, then Attach.");
            return false;
        }
        return true;
    }

    async void DoScan(ResourceRow r, bool first)
    {
        if (!CheckAttached()) return;
        double target;
        if (!TryNum(r.TxtSeen.Text, out target)) { MessageBox.Show("Type the number shown on your HUD."); return; }
        if (first && Math.Abs(target) < 2)
        {
            MessageBox.Show(r.Name + ": " + target + " is too common in memory to start a scan with. Wait until the value is 2 or more, then First Scan.");
            return;
        }
        var t = r.Type;
        bool exact = r.Exact;
        r.ChkFreeze.Checked = false;
        SetBusy(true);
        r.LblStatus.Text = "Scanning...";
        List<long> found;
        var prev = r.Candidates;
        try
        {
            found = await Task.Run(() =>
            {
                if (first) return mem.Scan(target, t, exact, null);
                if (prev.Count > 50000) return mem.Scan(target, t, exact, new HashSet<long>(prev));
                var keep = new List<long>();
                foreach (var a in prev)
                {
                    double v;
                    if (mem.ReadValue(a, t, out v) && Mem.Matches(v, target, t, exact)) keep.Add(a);
                }
                return keep;
            });
        }
        finally { SetBusy(false); }
        if (found == null)
        {
            ResetRow(r);
            MessageBox.Show(r.Name + ": too many matches (this number is very common in memory). Wait until it is bigger or less round, then First Scan again.");
            return;
        }
        r.Candidates = found;
        bool any = found.Count > 0;
        r.BtnNext.Enabled = any;
        r.BtnSet.Enabled = r.BtnAdd.Enabled = r.ChkFreeze.Enabled = any;
        if (!any) r.LblStatus.Text = "-";
        UpdateStatus(r);
        if (!any)
            MessageBox.Show(r.Name + ": nothing matched. Check the number, or switch this row's Type and do a First Scan again.");
    }

    void SetBusy(bool busy)
    {
        UseWaitCursor = busy;
        foreach (var r in rows)
        {
            r.BtnFirst.Enabled = !busy;
            r.BtnNext.Enabled = !busy && r.Candidates.Count > 0;
        }
    }

    bool ConfirmWriteCount(ResourceRow r)
    {
        if (r.Candidates.Count <= MAX_WRITE) return true;
        MessageBox.Show(r.Name + ": still " + r.Candidates.Count.ToString("N0") +
            " possible addresses. Let the value change in game and use Next Scan until " + MAX_WRITE + " or fewer remain.");
        return false;
    }

    void DoSet(ResourceRow r, double? add)
    {
        if (!CheckAttached() || !ConfirmWriteCount(r)) return;
        var t = r.Type;
        int ok = 0;
        double newVal = 0;
        if (add == null && !TryNum(r.TxtNew.Text, out newVal)) { MessageBox.Show("Enter a valid new value."); return; }
        foreach (var a in r.Candidates)
        {
            double v = newVal;
            if (add != null)
            {
                double cur;
                if (!mem.ReadValue(a, t, out cur)) continue;
                v = Math.Max(0, cur + add.Value);
            }
            if (mem.Write(a, Mem.Encode(v, t))) ok++;
        }
        if (r.ChkFreeze.Checked && add == null) r.FreezeValue = newVal;
        UpdateStatus(r);
        if (ok == 0) MessageBox.Show("Write failed. Try running the trainer as Administrator.");
    }

    void UpdateStatus(ResourceRow r)
    {
        int n = r.Candidates.Count;
        if (n == 0) return;
        string s = n.ToString("N0") + " address" + (n == 1 ? "" : "es");
        if (n <= MAX_WRITE)
        {
            double v;
            if (mem.ReadValue(r.Candidates[0], r.Type, out v)) s += "  |  now: " + v.ToString("N0");
        }
        else s += "  (narrow down)";
        r.LblStatus.Text = s;
    }

    void Tick()
    {
        if (mem.Handle == IntPtr.Zero) return;
        if (!mem.Alive)
        {
            mem.Detach();
            lblAttach.Text = "Game closed"; lblAttach.ForeColor = Color.DarkRed;
            foreach (var r in rows) ResetRow(r);
            cheats.Reset();
            cheatStatus.Text = "Game closed."; cheatStatus.ForeColor = Color.DarkRed;
            return;
        }
        if (cheats.GameGlobal != 0)
        {
            cheatStatus.Text = cheats.Tick();
            cheatStatus.ForeColor = cheatStatus.Text.StartsWith("Active") ? Color.DarkGreen : Color.DarkOrange;
            UpdateShipLive();
        }
        foreach (var r in rows)
        {
            if (r.ChkFreeze.Checked && r.Candidates.Count <= MAX_WRITE)
            {
                var bytes = Mem.Encode(r.FreezeValue, r.Type);
                foreach (var a in r.Candidates) mem.Write(a, bytes);
            }
            if (r.Candidates.Count > 0 && r.Candidates.Count <= MAX_WRITE) UpdateStatus(r);
        }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        timer.Stop();
        if (mem.Handle != IntPtr.Zero && mem.Alive && cheats.GameGlobal != 0) cheats.RestoreAll();
        mem.Detach();
        base.OnFormClosed(e);
    }

    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new TrainerForm());
    }
}
