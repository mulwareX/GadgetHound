# GadgetHound

A command-line tool for searching, filtering, and analysing ROP gadget lists exported by tools like **ROPgadget**, **ropper**, and **pwntools**. Supports smart wildcard queries, register aliases, exclude filters, result highlighting, paging, and more.

---

## Features

- **Wildcard queries** — match one instruction (`*`) or any number of instructions (`**`)
- **Register aliases** — `%` for any `r32`, `%%` for `r16`, `%%%` for `r8`, `r/m32` for memory forms, `imm` for any immediate
- **Query highlighting** — matched (non-wildcard) instructions shown in **bold magenta** so hits stand out instantly
- **Exclude filters** — drop gadgets containing specific instructions or operands
- **Sort modes** — by length (`low` / `high`) or by where the match lands (`end`)
- **Paging** — pause every N results, great for PowerShell and narrow terminals
- **Interactive REPL** — stateful search session with history, toggles, and grep
- **Statistics** — mnemonic frequency, gadget length distribution, terminal instructions
- **UTF-16 BOM support** — auto-detects files produced by Windows ROP dumpers

---

## Requirements

- Python 3.7 or later
- No third-party dependencies — stdlib only

---

## Installation

```bash
git clone https://github.com/yourname/rop-gadget-search.git
cd rop-gadget-search
```

No install step needed. Run directly with Python.

---

## Generating a Gadget File

The tool accepts the standard output format used by ROPgadget, ropper, and pwntools.

**ROPgadget**
```bash
ROPgadget --binary target.elf --rop > gadgets.txt
```

**ropper**
```bash
ropper -f target.elf > gadgets.txt
```

**pwntools**
```python
from pwn import *
e = ELF("target.elf")
rop = ROP(e)
with open("gadgets.txt", "w") as f:
    f.write(str(rop))
```

---

## Usage

### Interactive REPL (default)

```bash
python rop_search.py gadgets.txt
```

Launches a stateful interactive session. Type `help` or `?` at the prompt for a full reference.

### Non-interactive (single query)

```bash
python rop_search.py gadgets.txt -q "pop ecx ; ret"
python rop_search.py gadgets.txt -q "** ; pop ecx ; ** ; ret" --sort low
python rop_search.py gadgets.txt -q "mov %, % ; ret" -e "* esp"
python rop_search.py gadgets.txt --writeaddr ebx eax
python rop_search.py gadgets.txt --stats
```

---

## CLI Reference

| Flag | Description |
|---|---|
| `file` | Path to gadget file (required) |
| `-q`, `--query` | Search query; skips interactive mode |
| `-e`, `--exclude` | Exclude filter (comma/semicolon-separated for multiple) |
| `-n`, `--max N` | Limit results to N |
| `--noesp` | Exclude gadgets with `add/sub/inc/dec` on `esp` |
| `--besp` | Include only gadgets that reference `esp` |
| `--sort low\|high\|end` | Sort by length or by match position (see below) |
| `--writeaddr A B` | Find `mov dword [A], B` gadgets |
| `--stats` | Print statistics for the gadget file and exit |
| `--page N` | Pause every N results (useful in PowerShell) |
| `--no-color` | Disable ANSI colour output |

---

## Wildcards

| Token | Meaning |
|---|---|
| `*` | Exactly **one** instruction (any mnemonic / operands) |
| `**` | **Zero or more** instructions |

```
pop ecx ; ret               — exact match, only these two instructions
* ; pop ecx ; ret           — one instruction before, then pop ecx, then ret
** ; pop ecx ; ** ; ret     — anything before and after, must end with ret
* ; * ; pop ecx             — exactly two instructions before pop ecx
```

---

## Register Aliases

| Token | Expands to |
|---|---|
| `%` | Any `r32`: `eax ecx edx ebx esp ebp esi edi` |
| `%%` | Any `r16`: `ax cx dx bx sp bp si di` |
| `%%%` | Any `r8`: `al ah cl ch dl dh bl bh` |
| `r32` | Same as `%` |
| `r16` | Same as `%%` |
| `r8` | Same as `%%%` |
| `r/m32` | Any `r32` or `dword [reg]` memory form |
| `imm` | Any immediate (`0x…` or decimal) |

```bash
python rop_search.py gadgets.txt -q "mov %, % ; ret"
python rop_search.py gadgets.txt -q "add r32, imm ; * ; ret"
python rop_search.py gadgets.txt -q "xor %, % ; ** ; ret"
python rop_search.py gadgets.txt -q "mov dword [%], % ; ret"
```

---

## Exclude Filters

Drop gadgets whose instruction list matches a filter. Multiple filters are comma or semicolon separated.

| Syntax | Effect |
|---|---|
| `"pop ebx"` | Drop gadgets containing exactly `pop ebx` |
| `"* ebx"` | Drop gadgets where **any** instruction mentions `ebx` as a whole word |
| `"pop ebx, * esp"` | Multiple excludes combined |

```bash
# CLI flag
python rop_search.py gadgets.txt -q "pop % ; ret" -e "* esp"

# Inline !not syntax
python rop_search.py gadgets.txt -q "** ; pop % ; ** ; ret !not pop esp, pop ebx"
```

---

## Sort Modes

### `--sort low` / `--sort high`

Sort results by gadget length (number of instructions), shortest or longest first.

```bash
python rop_search.py gadgets.txt -q "** ; pop ecx ; ** ; ret" --sort low
```

### `--sort end`

Sorts gadgets so that results where the **matched pattern falls closest to the end** of the gadget come first. The DP engine runs in rightmost-match mode — `**` wildcards prefer consuming more instructions, driving the match toward the tail.

This is useful when you want gadgets where your target sequence effectively *finishes* the gadget rather than appearing somewhere in the middle.

```bash
# Surfaces gadgets ending in "pop ecx … push esi"
python rop_search.py gadgets.txt -q "** ; pop ecx ; ** ; push esi ; **" --sort end
```

---

## Highlighting

Output colours indicate the role of each instruction:

| Colour | Meaning |
|---|---|
| **Bold magenta** | Matched by a literal pattern token (your actual search hit) |
| Cyan | Wildcard-matched or unmatched instruction |
| Red | Matched an exclude filter |
| Yellow | Gadget address |

---

## Paging (PowerShell / Narrow Terminals)

When there are many results, use `--page N` to pause every N lines.

```bash
python rop_search.py gadgets.txt -q "pop % ; ret" --page 20
```

At the pause prompt, press **Enter** to continue or **q** to stop.

In the REPL, use `set page 20` to enable or `set page off` to disable.

---

## Interactive REPL Commands

Launch without `-q` to enter the interactive REPL.

| Command | Description |
|---|---|
| `<query>` | Search using the query syntax above |
| `stats` | Print gadget file statistics |
| `list [N]` | Print first N gadgets (default 20) |
| `grep <text>` | Plain substring search across all gadgets |
| `set noesp` | Toggle `--noesp` filter on/off |
| `set besp` | Toggle `--besp` filter on/off |
| `set sort low\|high\|end\|off` | Change sort mode |
| `set page N\|off` | Enable or disable paging |
| `writeaddr A B` | Find `mov dword [A], B` gadgets |
| `help` / `?` | Print quick reference |
| `quit` / `exit` | Exit |

Active filters are shown in the prompt:

```
rop [noesp ↕end pg20]>
```

---

## Examples

```bash
# Find all "pop reg ; ret" gadgets, shortest first
python rop_search.py gadgets.txt -q "pop % ; ret" --sort low

# Find gadgets that write a register into memory
python rop_search.py gadgets.txt -q "mov dword [%], % ; ret"

# Find a mov gadget, excluding anything that touches esp or ebp
python rop_search.py gadgets.txt -q "mov %, % ; ret" -e "* esp, * ebp"

# Find where a pattern lands at the end of longer gadgets
python rop_search.py gadgets.txt -q "** ; xor %, % ; ** ; ret" --sort end

# Write-what-where gadget search
python rop_search.py gadgets.txt --writeaddr ebx eax

# Limit to 10 results, paged in groups of 5
python rop_search.py gadgets.txt -q "** ; ret" -n 10 --page 5

# Statistics for a gadget dump
python rop_search.py gadgets.txt --stats

# No colour (for piping to a file)
python rop_search.py gadgets.txt -q "pop ecx ; ret" --no-color > results.txt
```

---

## Output Format

```
  Found 4 gadget(s)

  0x080a1234  [3]  xor eax, eax ; pop ecx ; ret
  0x080b5678  [2]  pop ecx ; ret
  0x080c9abc  [4]  push esi ; xor eax, eax ; pop ecx ; ret
  0x080def01  [3]  mov eax, 0 ; pop ecx ; ret
```

- **Address** (yellow) — gadget location in the binary
- **`[N]`** — number of instructions in the gadget
- **Instructions** — coloured by match role (see Highlighting)

---

## License

MIT
