#!/usr/bin/env python3
"""
ROP Gadget Search v3  ·  Smart wildcard, alias & filter search
==============================================================
Usage:
    python rop_search.py gadgets.txt
    python rop_search.py gadgets.txt -q "** ; pop ecx ; ** ; ret"
    python rop_search.py gadgets.txt -q "mov %, % ; ret" -e "* esp"
    python rop_search.py gadgets.txt -q "* ; pop ecx ; * ; ret" --noesp --sort low
    python rop_search.py gadgets.txt -q "** ; pop ecx ; ** ; push esi ; **" --sort end
    python rop_search.py gadgets.txt --writeaddr ebx eax
    python rop_search.py gadgets.txt --stats
    python rop_search.py gadgets.txt -q "pop %" --page 20

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 WILDCARDS
    *         exactly ONE instruction  (any mnemonic/operands)
    **        ZERO or more instructions

 REGISTER ALIASES
    %         r32  →  eax ecx edx ebx esp ebp esi edi
    %%        r16  →  ax  cx  dx  bx  sp  bp  si  di
    %%%       r8   →  al  ah  cl  ch  dl  dh  bl  bh
    r/m32     r32 + dword [reg] memory forms
    imm       any immediate  (0x… or plain decimal)

 EXACT MATCH (no wildcards)
    "pop ecx ; ret"  →  only gadgets that are EXACTLY those two instructions

 HIGHLIGHTING
    Matched (non-wildcard) instructions are shown in bold magenta.
    Wildcard-matched instructions remain cyan.
    Excluded instructions are shown in red.

 SORT END
    --sort end  →  puts gadgets where the matched pattern falls
                   CLOSEST TO THE END first (rightmost match wins).
                   e.g. "** ; pop ecx ; ** ; push esi ; **" with --sort end
                   surfaces gadgets ending in  pop ecx … push esi.

 PAGING  (useful for PowerShell / narrow terminals)
    --page 20   pause every 20 results; press Enter to continue, q to stop.
    In REPL:    set page 20  /  set page off
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import re
import sys
import argparse
from collections import Counter

# Ensure Unicode output works on Windows terminals (CP1252 / PowerShell)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import readline          # arrow-key history in interactive mode
except ImportError:
    pass

# ══════════════════════════════════════════════════════════════════
#  Register tables
# ══════════════════════════════════════════════════════════════════
R32  = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
R16  = ["ax",  "cx",  "dx",  "bx",  "sp",  "bp",  "si",  "di" ]
R8   = ["al",  "ah",  "cl",  "ch",  "dl",  "dh",  "bl",  "bh" ]
RM32 = R32 + [f"dword [{r}]" for r in R32] + [f"[{r}]" for r in R32]

IMM_PAT   = r"(?:0x[0-9a-fA-F]+|\d+)"

def _alt(regs):
    return "(?:" + "|".join(re.escape(r) for r in regs) + ")"

_R32_ALT  = _alt(R32)
_R16_ALT  = _alt(R16)
_R8_ALT   = _alt(R8)
_RM32_ALT = _alt(RM32)

_NAMED = [
    ("r/m32", _RM32_ALT),
    ("r32",   _R32_ALT),
    ("r16",   _R16_ALT),
    ("r8",    _R8_ALT),
    ("imm",   IMM_PAT),
]

# ══════════════════════════════════════════════════════════════════
#  Data model
# ══════════════════════════════════════════════════════════════════
class Gadget:
    __slots__ = ("address", "instructions", "raw")

    def __init__(self, addr: str, instrs: list, raw: str):
        self.address      = addr
        self.instructions = instrs
        self.raw          = raw

    def full_text(self) -> str:
        return " ; ".join(self.instructions)

    def __len__(self) -> int:
        return len(self.instructions)


# ══════════════════════════════════════════════════════════════════
#  Normalisation
# ══════════════════════════════════════════════════════════════════
def normalize(text: str) -> str:
    text = re.sub(r"\s*;\s*", " ; ", text)
    text = re.sub(r"\s*,\s*", ", ",  text)
    text = re.sub(r"\s+",     " ",   text)
    return text.strip()


# ══════════════════════════════════════════════════════════════════
#  File parser
# ══════════════════════════════════════════════════════════════════
_LINE_RE = re.compile(
    r"^(0x[0-9a-fA-F]+)\s*:\s*(.+?)(?:\s*\(\d+\s*found\))?\s*$"
)

def _has_utf16_bom(path: str) -> bool:
    with open(path, "rb") as f:
        bom = f.read(2)
    return bom in (b"\xff\xfe", b"\xfe\xff")

def parse_file(path: str) -> list:
    gadgets = []
    encoding = "utf-16" if _has_utf16_bom(path) else None
    open_kwargs = {"encoding": encoding} if encoding else {"errors": "replace"}
    with open(path, **open_kwargs) as fh:
        for line in fh:
            m = _LINE_RE.match(line.rstrip())
            if not m:
                continue
            parts = [normalize(p) for p in m.group(2).split(";") if p.strip()]
            if parts:
                gadgets.append(Gadget(m.group(1), parts, line.rstrip()))
    return gadgets


# ══════════════════════════════════════════════════════════════════
#  Alias expansion
# ══════════════════════════════════════════════════════════════════
_SPECIAL = set(r"\.^$+?{}[]|()")

def expand(text: str) -> str:
    out = []
    i   = 0
    n   = len(text)

    while i < n:
        ch = text[i]

        if ch == "%":
            if text[i:i+3] == "%%%":
                out.append(_R8_ALT);  i += 3; continue
            if text[i:i+2] == "%%":
                out.append(_R16_ALT); i += 2; continue
            out.append(_R32_ALT);     i += 1; continue

        if ch == " ":
            out.append(r"\s+")
            i += 1; continue

        if ch in _SPECIAL:
            out.append("\\" + ch)
            i += 1; continue

        matched = False
        for alias, alt in _NAMED:
            la = len(alias)
            if text[i:i+la].lower() == alias:
                pre_ok = i == 0 or not (text[i-1].isalnum() or text[i-1] in "_")
                suf_ok = (i+la >= n
                          or not (text[i+la].isalnum() or text[i+la] in "_/"))
                if pre_ok and suf_ok:
                    out.append(alt)
                    i += la
                    matched = True
                    break
        if matched:
            continue

        out.append(re.escape(ch))
        i += 1

    return "".join(out)


def _compile_instr(token: str):
    return re.compile(r"^\s*" + expand(token.strip()) + r"\s*$", re.IGNORECASE)


# ══════════════════════════════════════════════════════════════════
#  Query tokeniser
# ══════════════════════════════════════════════════════════════════
def tokenize(query: str) -> list:
    return [t.strip() for t in normalize(query).split(";") if t.strip()]


# ══════════════════════════════════════════════════════════════════
#  DP matcher  —  returns frozenset of matched instruction indices
#                 (non-wildcard hits only), or None on no match.
#
#  This single function replaces both the old _dp (bool) and adds
#  index tracking for:
#    • highlighting matched instructions in output
#    • "sort end" scoring  (rightmost last-hit = closest to gadget end)
#
#  Wildcards:
#    "*"   → exactly ONE instruction  (index NOT added to hit set)
#    "**"  → ZERO or more instructions (greedy-left, tries smallest skip
#             first so the standard match is "leftmost / shortest fit")
#
#  sort_end=True flips "**" to try the LARGEST skip first, which drives
#  the match as far right as possible — used when scoring for sort-end.
# ══════════════════════════════════════════════════════════════════
def _dp_hl(instrs: list, ii: int, pat: list, pi: int,
           memo: dict, compiled: dict,
           rightmost: bool = False):
    """
    Returns frozenset of instruction indices matched by *literal* pattern
    tokens, or None if the pattern does not match.
    rightmost=True → "**" tries consuming MORE instructions first (for sort-end scoring).
    """
    key = (ii, pi)
    if key in memo:
        return memo[key]

    # base case: consumed entire pattern
    if pi == len(pat):
        r = frozenset() if ii == len(instrs) else None
        memo[key] = r
        return r

    tok = pat[pi]

    # "**"  →  zero or more
    if tok == "**":
        n = len(instrs)
        rng = range(n, ii - 1, -1) if rightmost else range(ii, n + 1)
        r = None
        for skip in rng:
            candidate = _dp_hl(instrs, skip, pat, pi + 1,
                               memo, compiled, rightmost)
            if candidate is not None:
                r = candidate
                break
        memo[key] = r
        return r

    # "*"  →  exactly one (no highlight)
    if tok == "*":
        if ii >= len(instrs):
            memo[key] = None
            return None
        r = _dp_hl(instrs, ii + 1, pat, pi + 1, memo, compiled, rightmost)
        memo[key] = r
        return r

    # literal instruction token
    if ii >= len(instrs):
        memo[key] = None
        return None

    if tok not in compiled:
        try:
            compiled[tok] = _compile_instr(tok)
        except re.error:
            compiled[tok] = None

    rx = compiled[tok]
    if not (rx and rx.match(instrs[ii])):
        memo[key] = None
        return None

    r = _dp_hl(instrs, ii + 1, pat, pi + 1, memo, compiled, rightmost)
    if r is not None:
        r = frozenset([ii]) | r

    memo[key] = r
    return r


# ══════════════════════════════════════════════════════════════════
#  Exclude filters
# ══════════════════════════════════════════════════════════════════
def _build_excl(token: str):
    token = token.strip()
    m = re.match(r"^\*\s+(.+)$", token)
    if m:
        operand = m.group(1).strip()
        pat = re.compile(
            r"(?<![a-zA-Z0-9_])" + re.escape(operand) + r"(?![a-zA-Z0-9_])",
            re.IGNORECASE,
        )
        return lambda instr, p=pat: bool(p.search(instr))
    else:
        rx = _compile_instr(token)
        return lambda instr, r=rx: bool(r.match(instr))


def parse_excludes(excl_str: str) -> list:
    fns = []
    for tok in re.split(r"[,;]", excl_str):
        tok = tok.strip()
        if tok:
            try:
                fns.append(_build_excl(tok))
            except re.error:
                pass
    return fns


def gadget_excluded(gadget: Gadget, excl_fns: list) -> bool:
    return any(fn(i) for fn in excl_fns for i in gadget.instructions)


# ══════════════════════════════════════════════════════════════════
#  Special filters
# ══════════════════════════════════════════════════════════════════
_NOESP_RE = re.compile(
    r"^\s*(?:add|sub|inc|dec|imul|mul|idiv|div|neg|adc|sbb)\s+esp\b",
    re.IGNORECASE,
)
_ESP_RE = re.compile(r"\besp\b", re.IGNORECASE)


def has_esp_arith(g: Gadget) -> bool:
    return any(_NOESP_RE.match(i) for i in g.instructions)


def has_esp_ref(g: Gadget) -> bool:
    return any(_ESP_RE.search(i) for i in g.instructions)


def build_writeaddr(addr1: str, addr2: str):
    a1 = expand(addr1.strip())
    a2 = expand(addr2.strip())
    return re.compile(
        r"^\s*mov\s+dword\s+\[\s*" + a1 + r"\s*\]\s*,\s*" + a2 + r"\s*$",
        re.IGNORECASE,
    )


# ══════════════════════════════════════════════════════════════════
#  Core search
#
#  Returns list of (Gadget, hit_frozenset_or_None) tuples.
#  hit_frozenset contains indices of instructions matched by
#  *literal* (non-wildcard) pattern tokens — used for highlighting
#  and sort-end scoring.
# ══════════════════════════════════════════════════════════════════
def do_search(gadgets: list, *,
              pattern=None, excl_fns=None, max_n=None,
              noesp=False, besp=False, writeaddr_rx=None,
              sort_order=None):

    compiled = {}
    results  = []   # list of (Gadget, frozenset | None)

    for g in gadgets:
        hl = None
        if pattern is not None:
            hl = _dp_hl(g.instructions, 0, pattern, 0, {}, compiled,
                        rightmost=(sort_order == "end"))
            if hl is None:
                continue

        if excl_fns     and gadget_excluded(g, excl_fns):
            continue
        if noesp        and has_esp_arith(g):
            continue
        if besp         and not has_esp_ref(g):
            continue
        if writeaddr_rx and not any(writeaddr_rx.match(i) for i in g.instructions):
            continue

        results.append((g, hl))
        if max_n and len(results) >= max_n:
            break

    # ── sorting ───────────────────────────────────────────────────
    if sort_order == "low":
        results.sort(key=lambda x: len(x[0]))

    elif sort_order == "high":
        results.sort(key=lambda x: len(x[0]), reverse=True)

    elif sort_order == "end":
        # Score = how many instructions appear AFTER the last hit.
        # Lower score → hit is closer to the tail of the gadget.
        def end_key(x):
            g, hl = x
            if hl:
                return len(g) - 1 - max(hl)
            return len(g)
        results.sort(key=end_key)

    return results


# ══════════════════════════════════════════════════════════════════
#  Colour helpers
# ══════════════════════════════════════════════════════════════════
RS   = "\033[0m"
BOLD = "\033[1m"
GRN  = "\033[92m"
CYN  = "\033[96m"
YLW  = "\033[93m"
RED  = "\033[91m"
DIM  = "\033[2m"
MAG  = "\033[95m"
BLU  = "\033[94m"

# ── NEW: highlight colour for matched (non-wildcard) instructions ──
# Bold bright-magenta so it stands out from cyan (unmatched) and
# yellow (address).  Works in both cmd.exe and PowerShell with
# VirtualTerminalLevel enabled (Windows 10+ default).
HMAG = "\033[1;95m"


def c(txt: str, *codes, cl: bool = True) -> str:
    return ("".join(codes) + txt + RS) if cl else txt


# ══════════════════════════════════════════════════════════════════
#  Pager helper
# ══════════════════════════════════════════════════════════════════
def _pager_pause(cl: bool) -> bool:
    """
    Print a 'more' prompt and wait for input.
    Returns True to continue, False to stop.
    """
    try:
        ans = input(
            c("  -- press Enter for more (q = stop) -- ", DIM, cl=cl)
        ).strip().lower()
        # Clear the prompt line (move up 1, erase line)
        if cl:
            sys.stdout.write("\033[1A\033[2K")
            sys.stdout.flush()
        return ans != "q"
    except (EOFError, KeyboardInterrupt):
        print()
        return False


# ══════════════════════════════════════════════════════════════════
#  Output
# ══════════════════════════════════════════════════════════════════
def print_results(results: list, excl_fns: list, cl: bool,
                  page_size: int = None) -> None:
    """
    results  : list of (Gadget, frozenset|None) from do_search()
    excl_fns : exclude filter functions (matched instrs shown in red)
    cl       : colour flag
    page_size: if set, pause every page_size lines
    """
    total = len(results)
    header = f"  Found {total} gadget(s)"
    print(f"\n{c(header, BOLD, GRN, cl=cl)}\n")

    for idx, (g, hl) in enumerate(results):
        parts = []
        for ii, ins in enumerate(g.instructions):
            is_excl    = bool(excl_fns and any(fn(ins) for fn in excl_fns))
            is_hit     = bool(hl and ii in hl)

            if is_excl:
                colour = RED               # excluded instruction
            elif is_hit:
                colour = HMAG             # matched non-wildcard instruction
            else:
                colour = CYN              # wildcard-matched or unmatched

            parts.append(c(ins, colour, cl=cl))

        sep  = c(" ; ", DIM, cl=cl)
        cnt  = c(f"[{len(g)}]", DIM, cl=cl)
        addr = c(g.address, YLW, cl=cl)
        print(f"  {addr}  {cnt}  {sep.join(parts)}")

        # paging: pause after every page_size results (not after the last)
        if page_size and (idx + 1) % page_size == 0 and (idx + 1) < total:
            if not _pager_pause(cl):
                print()
                return

    print()


# ══════════════════════════════════════════════════════════════════
#  Statistics
# ══════════════════════════════════════════════════════════════════
def print_stats(gadgets: list, cl: bool) -> None:
    total = len(gadgets)
    if not total:
        print("  No gadgets loaded.\n")
        return

    mnems = Counter(
        g.instructions[0].split()[0].lower() for g in gadgets if g.instructions
    )
    ends  = Counter(
        g.instructions[-1].strip().lower() for g in gadgets if g.instructions
    )
    lens  = Counter(len(g) for g in gadgets)
    W     = 26
    div   = "-" * 70

    def bar(n):
        f = int(n / total * W)
        return "█" * f + "░" * (W - f)

    print(f"\n{div}")
    print(f"  Total gadgets : {c(str(total), BOLD, GRN, cl=cl)}")
    print(f"\n  Top 10 leading mnemonics:")
    for mn, cnt in mnems.most_common(10):
        print(c(f"    {mn:<16}{cnt:>6}  {bar(cnt)}  {cnt/total*100:5.1f}%",
                CYN, cl=cl))
    print(f"\n  Top 10 terminal instructions:")
    for en, cnt in ends.most_common(10):
        print(c(f"    {en:<42}{cnt:>6}", YLW, cl=cl))
    print(f"\n  Gadget length distribution:")
    for ln in sorted(lens):
        print(f"    {ln:>2} instr : {lens[ln]:>6}  {bar(lens[ln])}")
    print(f"{div}\n")


# ══════════════════════════════════════════════════════════════════
#  Help text
# ══════════════════════════════════════════════════════════════════
HELP = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                     GadgetHound — By Mulware                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  WILDCARDS                                                                  ║
║    *          exactly ONE instruction (any mnemonic / operands)            ║
║    **         ZERO or more instructions                                    ║
║                                                                             ║
║  REGISTER ALIASES                                                           ║
║    %          r32 :  eax  ecx  edx  ebx  esp  ebp  esi  edi               ║
║    %%         r16 :  ax   cx   dx   bx   sp   bp   si   di                ║
║    %%%        r8  :  al   ah   cl   ch   dl   dh   bl   bh                ║
║    r/m32      r32 + dword [reg] memory operands                            ║
║    imm        any immediate  (0x… or decimal)                              ║
║                                                                             ║
║  QUERY EXAMPLES                                                             ║
║    pop ecx ; ret              EXACT — only these two instructions          ║
║    * ; pop ecx ; * ; ret      one instr before, one after, then ret        ║
║    ** ; pop ecx ; ** ; ret    anything before/after, ends with ret         ║
║    mov %, ebx ; ret           mov <any r32>, ebx then ret                  ║
║    xor %, % ; ** ; ret        xor any pair + zero-or-more instrs + ret     ║
║                                                                             ║
║  HIGHLIGHTING                                                               ║
║    Matched instructions (non-wildcard hits) → bold magenta                 ║
║    Wildcard-matched instructions            → cyan                         ║
║    Excluded instructions                    → red                          ║
║                                                                             ║
║  EXCLUDE  (-e / --exclude  or inline  !not)                                ║
║    -e "pop ebx"               drop gadgets containing pop ebx              ║
║    -e "* ebx"                 drop any gadget with any use of ebx          ║
║    -e "pop ebx, * esp"        multiple excludes (comma-separated)          ║
║    ** ; pop % ; ** ; ret  !not pop ebx, pop esp                            ║
║                                                                             ║
║  SPECIAL FLAGS  (CLI and REPL "set" command)                                ║
║    --noesp          exclude gadgets with add/sub/inc/dec/… on esp          ║
║    --besp           include only gadgets that reference esp at all         ║
║    --sort low       shortest gadgets first                                 ║
║    --sort high      longest gadgets first                                  ║
║    --sort end       gadgets where the match falls CLOSEST TO THE END first ║
║                     (useful to find patterns that finish the gadget)       ║
║    --writeaddr A B  find:  mov dword [A], B                               ║
║    --page N         pause every N results (great for PowerShell)           ║
║                                                                             ║
║  INTERACTIVE COMMANDS                                                       ║
║    stats                      gadget file statistics                       ║
║    list [N]                   first N gadgets (default 20)                ║
║    grep <text>                substring search                             ║
║    set noesp                  toggle --noesp filter                        ║
║    set besp                   toggle --besp filter                         ║
║    set sort low|high|end|off  change sort order                            ║
║    set page N|off             set pager (N lines per page, off=disable)    ║
║    writeaddr A B              find: mov dword [A], B                      ║
║    help / ?                   this screen                                  ║
║    quit / exit                                                             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


# ══════════════════════════════════════════════════════════════════
#  Inline  !not  parser
# ══════════════════════════════════════════════════════════════════
def split_not(raw: str):
    m = re.search(r"\s+!not\s+(.+)$", raw, re.IGNORECASE)
    if m:
        return raw[:m.start()].strip(), m.group(1).strip()
    return raw, ""


# ══════════════════════════════════════════════════════════════════
#  ASCII banner
# ══════════════════════════════════════════════════════════════════
BANNER = r"""
   ██████╗  █████╗ ██████╗  ██████╗ ███████╗████████╗  ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗
  ██╔════╝ ██╔══██╗██╔══██╗██╔════╝ ██╔════╝╚══██╔══╝  ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
  ██║  ███╗███████║██║  ██║██║  ███╗█████╗     ██║     ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
  ██║   ██║██╔══██║██║  ██║██║   ██║██╔══╝     ██║     ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
  ╚██████╔╝██║  ██║██████╔╝╚██████╔╝███████╗   ██║     ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
   ╚═════╝ ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝
                                                                                     By Mulware
"""


# ══════════════════════════════════════════════════════════════════
#  Interactive REPL
# ══════════════════════════════════════════════════════════════════
def run_repl(gadgets: list, cl: bool, default_page: int = None) -> None:
    noesp      = False
    besp       = False
    sort_order = None          # None | "low" | "high" | "end"
    page_size  = default_page  # None = no paging

    print(c(BANNER, MAG, cl=cl))
    print(
        f"  Loaded {c(str(len(gadgets)), BOLD, GRN, cl=cl)} gadgets.  "
        f"Type {c('help', CYN, cl=cl)} or {c('?', CYN, cl=cl)} for usage.\n"
    )

    while True:
        flags = []
        if noesp:      flags.append(c("noesp",          RED, cl=cl))
        if besp:       flags.append(c("besp",           BLU, cl=cl))
        if sort_order: flags.append(c(f"↕{sort_order}", YLW, cl=cl))
        if page_size:  flags.append(c(f"pg{page_size}", DIM, cl=cl))
        suffix = (" [" + " ".join(flags) + "]") if flags else ""

        try:
            raw = input(
                c("rop", BOLD, YLW, cl=cl) + suffix + c("> ", BOLD, YLW, cl=cl)
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not raw:
            continue
        lraw = raw.lower()

        if lraw in ("quit", "exit", "q"):
            print("Bye.")
            break

        if lraw in ("help", "?"):
            print(HELP)
            continue

        if lraw == "stats":
            print_stats(gadgets, cl)
            continue

        if lraw.startswith("list"):
            pts = lraw.split()
            n   = int(pts[1]) if len(pts) > 1 and pts[1].isdigit() else 20
            for g in gadgets[:n]:
                print(f"  {g.address}  [{len(g)}]  {g.full_text()}")
            print()
            continue

        if lraw.startswith("grep "):
            term  = raw[5:].strip().lower()
            found = [g for g in gadgets if term in g.full_text().lower()]
            print(f"\n{c(f'  grep: {len(found)} result(s)', BOLD, GRN, cl=cl)}\n")
            shown = 0
            for g in found:
                print(f"  {g.address}  [{len(g)}]  {g.full_text()}")
                shown += 1
                if page_size and shown % page_size == 0 and shown < len(found):
                    if not _pager_pause(cl):
                        break
            if len(found) > 200 and not page_size:
                print(f"  … (showing first 200 of {len(found)}, use --page or set page N)")
            print()
            continue

        if lraw.startswith("set "):
            pts = raw.split()
            if len(pts) >= 2:
                sub = pts[1].lower()
                if sub == "noesp":
                    noesp = not noesp
                    state = c("ON", GRN, cl=cl) if noesp else c("off", DIM, cl=cl)
                    print(f"  noesp → {state}\n")
                elif sub == "besp":
                    besp = not besp
                    state = c("ON", GRN, cl=cl) if besp else c("off", DIM, cl=cl)
                    print(f"  besp  → {state}\n")
                elif sub == "sort" and len(pts) >= 3:
                    v          = pts[2].lower()
                    sort_order = None if v == "off" else v
                    if sort_order not in (None, "low", "high", "end"):
                        print("  sort options: low | high | end | off\n")
                        sort_order = None
                    else:
                        print(f"  sort  → {c(str(sort_order), YLW, cl=cl)}\n")
                elif sub == "page" and len(pts) >= 3:
                    v = pts[2].lower()
                    if v == "off":
                        page_size = None
                        print(f"  page  → {c('off', DIM, cl=cl)}\n")
                    elif v.isdigit() and int(v) > 0:
                        page_size = int(v)
                        print(f"  page  → {c(str(page_size), YLW, cl=cl)} lines\n")
                    else:
                        print("  Usage: set page <N>  or  set page off\n")
                else:
                    print("  Usage: set noesp | set besp | "
                          "set sort low|high|end|off | set page N|off\n")
            continue

        if lraw.startswith("writeaddr "):
            pts = raw.split(None, 2)
            if len(pts) == 3:
                try:
                    wa_rx = build_writeaddr(pts[1], pts[2])
                    res   = do_search(
                        gadgets,
                        writeaddr_rx=wa_rx,
                        noesp=noesp,
                        besp=besp,
                        sort_order=sort_order,
                    )
                    print_results(res, [], cl, page_size=page_size)
                except re.error as e:
                    print(f"  compile error: {e}\n")
            else:
                print("  Usage: writeaddr <addr_or_reg> <src_or_reg>\n")
            continue

        # ── normal search query ────────────────────────────────────────────
        q_str, iex = split_not(raw)

        excl_str = iex
        if not excl_str:
            try:
                excl_str = input(
                    c('  exclude  (e.g. "pop ebx"  or  "* ebx",  Enter=none): ',
                      DIM, cl=cl)
                ).strip()
            except (EOFError, KeyboardInterrupt):
                excl_str = ""

        lim = ""
        try:
            lim = input(c("  max results (Enter=all): ", DIM, cl=cl)).strip()
        except (EOFError, KeyboardInterrupt):
            pass

        max_n    = int(lim) if lim.isdigit() else None
        excl_fns = parse_excludes(excl_str) if excl_str else []
        pattern  = tokenize(q_str)

        results = do_search(
            gadgets,
            pattern    = pattern or None,
            excl_fns   = excl_fns or None,
            max_n      = max_n,
            noesp      = noesp,
            besp       = besp,
            sort_order = sort_order,
        )
        print_results(results, excl_fns, cl, page_size=page_size)

        if not results:
            print(
                c(
                    "  Tip: * = one instr  **= zero-or-more  "
                    "% = any r32  %% = any r16  %%% = any r8  imm = any immediate\n",
                    DIM,
                    cl=cl,
                )
            )


# ══════════════════════════════════════════════════════════════════
#  CLI entry-point
# ══════════════════════════════════════════════════════════════════
def main() -> None:
    ap = argparse.ArgumentParser(
        description="ROP Gadget Search v3 — smart wildcard, alias & filter search",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("file",
                    help="Gadget file (ROPgadget / ropper / pwntools output)")
    ap.add_argument("-q", "--query",   default=None,
                    help="Search query (skips interactive mode)")
    ap.add_argument("-e", "--exclude", default="",
                    help='Exclude filter, e.g. "pop ebx" or "* ebx" '
                         "(comma/semicolon-separated for multiple)")
    ap.add_argument("-n", "--max",     type=int,
                    help="Maximum number of results to display")
    ap.add_argument("--noesp",   action="store_true",
                    help="Exclude gadgets that add/sub/inc/dec esp")
    ap.add_argument("--besp",    action="store_true",
                    help="Only gadgets that reference esp in any way")
    ap.add_argument("--sort",    choices=["low", "high", "end"],
                    help="Sort: low=shortest first  high=longest first  "
                         "end=pattern closest to gadget tail first")
    ap.add_argument("--writeaddr", nargs=2, metavar=("ADDR", "SRC"),
                    help="Find gadgets containing: mov dword [ADDR], SRC")
    ap.add_argument("--stats",   action="store_true",
                    help="Print gadget file statistics and exit")
    ap.add_argument("--page",    type=int, metavar="N", default=None,
                    help="Pause every N results (useful in PowerShell / "
                         "terminals without scrollback)")
    ap.add_argument("--no-color", action="store_true",
                    help="Disable ANSI colour output")
    args = ap.parse_args()

    cl = sys.stdout.isatty() and not args.no_color

    print(f"  Loading {args.file} …", end=" ", flush=True)
    try:
        gadgets = parse_file(args.file)
    except FileNotFoundError:
        print(f"\n  ERROR: file not found — {args.file}")
        sys.exit(1)
    print(f"{len(gadgets)} gadgets loaded.")

    if args.stats:
        print_stats(gadgets, cl)
        return

    writeaddr_rx = None
    if args.writeaddr:
        try:
            writeaddr_rx = build_writeaddr(args.writeaddr[0], args.writeaddr[1])
        except re.error as e:
            print(f"  --writeaddr compile error: {e}")
            sys.exit(1)

    if args.query or writeaddr_rx:
        q_str, iex = split_not(args.query or "")
        excl_str   = args.exclude or iex
        excl_fns   = parse_excludes(excl_str) if excl_str else []
        pattern    = tokenize(q_str) if q_str else []

        results = do_search(
            gadgets,
            pattern      = pattern or None,
            excl_fns     = excl_fns or None,
            max_n        = args.max,
            noesp        = args.noesp,
            besp         = args.besp,
            writeaddr_rx = writeaddr_rx,
            sort_order   = args.sort,
        )
        print_results(results, excl_fns, cl, page_size=args.page)

    else:
        run_repl(gadgets, cl, default_page=args.page)


if __name__ == "__main__":
    main()