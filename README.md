# Black Hat MEA CTF Qualification 2026

Writeups and solution artifacts.

## Writeups

| Challenge | Category | Flag |
|---|---|---|
| [Qfact](forensics/Qfact/) | Forensics | `BHFlagY{d3f3nd3r_qu4r4nt1n3_r3c0v3ry_2026}` |
| [Whisper](forensics/Whisper/) | Forensics | `BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}` |

## Repository layout

Each challenge lives in `<category>/<name>/` and contains:

* `README.md` — the step-by-step writeup
* `writeup.html` — the same writeup as a standalone page
* `solve/` — reproducible solution scripts
* `artifacts/` — recovered output (and, where relevant, recovered samples)

## A note on samples

Some challenges yield real malware. Anything of that kind is stored with a neutralised file
extension and a `README.md` alongside it stating the hashes and what the sample does. Nothing
in this repository is safe to run outside an isolated analysis VM.
