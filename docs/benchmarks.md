# Benchmarks

How to reproduce the measurements, and what they actually mean. **No numbers are
quoted here that were not produced by a run on the development machine** — run
the commands below and the results are written to `bench_data/`.

## Reproduce

```powershell
.venv\Scripts\python.exe -m pytest -q          # correctness gate
.venv\Scripts\python.exe gauntlet\benchmarks.py
.venv\Scripts\python.exe gauntlet\demo.py
```

`gauntlet/benchmarks.py` writes `bench_data/BENCHMARK_RESULTS.json`; the demo
runner writes its own artefacts to `bench_data/` as it goes.

## What is measured

| Measurement | Method | What it tells you |
|---|---|---|
| ML-KEM-768 / ML-DSA-65 latency | timed over repeated operations | post-quantum cost on this hardware |
| Shamir split and reconstruct | `(t=3, n=4)` over a 32-byte secret | whether key management is a bottleneck |
| Merkle build and proof | varying leaf counts | ledger overhead per block |
| Imperceptibility | variant A and variant B rendered at 150 dpi, PSNR computed between them | how visible the watermark is |
| Text integrity | extracted text of both variants compared | the watermark changes no words |
| Codeword recovery | embedded codeword re-extracted from the rendered file | the channel is lossless in the no-attack case |

## Reading the numbers honestly

- **PSNR is a weak proxy for invisibility.** A high PSNR between the two
  variants says the *difference* is small in aggregate; it does not say a reader
  cannot see the spacing, and it says nothing about what happens after a
  re-save, a print, or a screenshot.
- **Codeword recovery is measured on an untouched file.** Extraction strategy 1
  reads the `Tw` operators out of the content stream, so it reports 100%
  recovery with confidence `1.0` on any file that still carries them. The
  geometric strategy is the one that would survive re-rendering, and it is the
  weaker of the two. A benchmark on the un-attacked file therefore flatters the
  system; see `docs/threat-model.md` §4.5.
- **Latency is single-process, local, and CPU-bound.** There is no network in the
  measurement, which is the point of the design and also means these numbers say
  nothing about a networked deployment.
- **The multi-block scaling figures in the inherited documentation were not
  reproduced here.** They quoted false-accusation bounds for `M = 6 … 420`
  blocks; the `M = 420` figure in particular was not reproducible from this code
  and is not repeated. Regenerate with `gauntlet/distribution.py` at larger
  recipient counts if you need scaling data.

## Attack coverage

`gauntlet/attacks/` holds the adversarial scenarios the demo runs against. They
are demonstrations, not a security test suite:

| Script | Scenario | Expected outcome |
|---|---|---|
| `bypass_client.py` | rogue client skips the ledger | decryption fails; ciphertext useless |
| `tamper_database.py` | administrator edits a committed row | integrity scan fails; node flagged |
| `collude_splicing.py` | two recipients splice pages | both colluders surface above baseline |

None of these is covered by `pytest`; they are run interactively via
`gauntlet/demo.py` because they print rather than assert.
