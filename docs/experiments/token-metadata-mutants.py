"""Hand-applied mutation testing for the token metadata (ADR-0028).

Each entry replaces one guard with a weakened form and checks that the test
suite fails. A mutant that SURVIVES is a guard nothing tests.

Covers the pre-submission checks (ops::preflight) and the account decoder
(solana::rpc::decode_pending_action) added in Phase 7i-1.

Two traps this harness fell into first, both of which made mutants look
killed-or-clean when they were neither:

  * `cargo test --lib a b c` is a USAGE ERROR, not three filters. It exits
    non-zero having run nothing. Filters go after `--`.
  * Restoring the file with `shutil.move` gives it the BACKUP's mtime, which
    is older than the artifact built from the mutant — so cargo keeps the
    mutated build and the next run reports nonsense. Hence the `os.utime`.

A mutation harness that reports everything killed for mechanical reasons is
worse than no harness at all, so both are guarded here rather than
remembered.

Run from anywhere: `python3 docs/experiments/token-metadata-mutants.py`
"""
import subprocess, sys, shutil, os

ROOT = "/home/reaper/glc-solana-bridge/relayer"

MUTANTS = [
 # --- relayer encoding -------------------------------------------------
 ("M1 metadata PDA derived under our program, not Metaplex", "src/solana/instruction.rs",
  "        &TOKEN_METADATA_PROGRAM_ID,\n    )\n}",
  "        &solana_sdk::system_program::id(),\n    )\n}"),
 ("M2 uri length prefix dropped", "src/solana/instruction.rs",
  "    data.extend_from_slice(&(uri.len() as u32).to_le_bytes());\n    data.extend_from_slice(uri.as_bytes());",
  "    data.extend_from_slice(uri.as_bytes());"),
 ("M3 metadata account marked read-only", "src/solana/instruction.rs",
  "            AccountMeta::new(token_metadata_pda(wrapped_mint).0, false),",
  "            AccountMeta::new_readonly(token_metadata_pda(wrapped_mint).0, false),"),
 ("M4 admin no longer signs", "src/solana/instruction.rs",
  "            AccountMeta::new(*admin, true),\n            AccountMeta::new_readonly(bridge_config_pda(program_id).0, false),\n            AccountMeta::new_readonly(mint_authority_pda(program_id).0, false),",
  "            AccountMeta::new(*admin, false),\n            AccountMeta::new_readonly(bridge_config_pda(program_id).0, false),\n            AccountMeta::new_readonly(mint_authority_pda(program_id).0, false),"),
 ("M5 display name changed", "src/solana/instruction.rs",
  'pub const WRAPPED_GLC_NAME: &str = "Wrapped Goldcoin";',
  'pub const WRAPPED_GLC_NAME: &str = "wGLC";'),
 ("M6 symbol changed", "src/solana/instruction.rs",
  'pub const WRAPPED_GLC_SYMBOL: &str = "wGLC";',
  'pub const WRAPPED_GLC_SYMBOL: &str = "WGLC";'),
 # --- relayer decoder --------------------------------------------------
 ("D6 NUL padding not stripped", "src/solana/rpc.rs",
  "        Ok(String::from_utf8_lossy(raw)\n            .trim_end_matches('\\0')\n            .to_string())",
  "        Ok(String::from_utf8_lossy(raw).to_string())"),
 ("D7 metadata strings read from a fixed offset", "src/solana/rpc.rs",
  "        off += 4 + len;",
  "        off += 4 + 32;"),
 ("D8 update authority and mint swapped", "src/solana/rpc.rs",
  "    let update_authority = Pubkey::try_from(data.get(1..33).ok_or_else(|| need(\"update authority\"))?)",
  "    let update_authority = Pubkey::try_from(data.get(33..65).ok_or_else(|| need(\"update authority\"))?)"),
]

def run(cmd, cwd=ROOT):
    return subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True)

survived, killed, broken = [], [], []
for name, path, old, new in MUTANTS:
    full = os.path.join(ROOT, path)
    src = open(full).read()
    if old not in src:
        broken.append((name, "pattern not found"))
        continue
    shutil.copy(full, full + ".bak")
    open(full, "w").write(src.replace(old, new, 1))
    a = run("cargo test --lib -- solana::")
    b = run("cargo test -p glc-bridge --test admin_governance_encoding --test token_metadata",
            cwd="/home/reaper/glc-solana-bridge")
    shutil.move(full + ".bak", full)
    os.utime(full, None)  # restore bumps mtime; otherwise cargo keeps the mutant build

    # Exit CODES, not a count of "test result: ok" lines.
    #
    # The count-based check this replaced misreported every mutant the moment
    # a second test binary was added to one command: a failure in the first
    # still left enough "ok" lines from the second to clear the threshold, so
    # nine killed mutants reported as survivors. Fourth distinct harness
    # misreport in this project, and the first caused by editing the harness
    # itself.
    out = a.stdout + a.stderr + b.stdout + b.stderr
    compiled = "error[" not in out and "could not compile" not in out
    if not compiled:
        broken.append((name, "did not compile"))
    elif a.returncode != 0 or b.returncode != 0:
        killed.append(name)
    else:
        survived.append(name)
    print(f"{'KILLED  ' if name in killed else 'SURVIVED' if name in survived else 'BROKEN  '} {name}", flush=True)

print("\n=== summary ===")
print(f"killed:   {len(killed)}")
print(f"survived: {len(survived)}")
for s in survived: print("  SURVIVED:", s)
for b in broken: print("  BROKEN:", b)
