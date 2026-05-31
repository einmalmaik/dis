# Licensing, Branding & Trademark

## Requirement

> Open Source, aber NICHT frei für kommerzielle Nutzung. Lizenzierung
> vorbereiten. Branding: „Powered by DIS — Defensive Integration Shield".

## Honest framing first

A truly **OSI-"open source"** license (per the Open Source Definition, item 6 —
"No Discrimination Against Fields of Endeavor") **cannot** forbid commercial
use. So "open source but not free for commercial use" is, strictly,
**source-available / noncommercial**, not OSI-open-source. We use that term
honestly rather than mislabel the project.

## Options evaluated

| Option | Restricts commercial use? | OSI-approved? | npm/ecosystem fit | Verdict |
| --- | --- | --- | --- | --- |
| **AGPL-3.0** | No (only forces source disclosure for network use) | Yes | Good, but copyleft scares integrators and does **not** meet "not free for commercial use" | Rejected — wrong tool; doesn't restrict commercial use |
| **MIT/Apache + Commons Clause** | Yes (bans "selling") | No (Commons Clause negates OSI status) | Workable but ambiguous wording; "selling" is narrow and litigated | Rejected — vague scope, reputational baggage |
| **PolyForm Noncommercial 1.0.0** | **Yes, explicitly** | No (by design) | Plain-text, SPDX-listed (`PolyForm-Noncommercial-1.0.0`), purpose-built, clear definitions | **Chosen** |
| Custom EULA | Yes | No | Poor (untrusted, unaudited terms) | Rejected — never roll your own license |

## Decision

**Primary license: PolyForm Noncommercial 1.0.0** (see [`/LICENSE`](../LICENSE)).

Rationale:
- It does exactly what is asked: **any noncommercial purpose is permitted; all
  commercial use requires a separate license.** No ambiguity about "selling".
- It is professionally drafted (PolyForm), SPDX-recognised, and far clearer than
  a Commons Clause bolt-on.
- It keeps the door open for **dual licensing**: the copyright holder may grant
  commercial licenses separately (see below).

**Commercial use: dual-licensing.** Commercial users obtain a separate
commercial license from the copyright holder. Because the licensor owns the
code (and requires a CLA from contributors), it can offer commercial terms
without conflict. This is the standard "open-core / source-available + commercial"
model.

## package.json

`"license": "SEE LICENSE IN LICENSE"` (npm-valid for non-OSI licenses) with the
full PolyForm text shipped in `LICENSE`. SPDX id for tooling:
`PolyForm-Noncommercial-1.0.0`.

## Contributor rules (CLA)

To preserve the ability to dual-license, every contributor must agree that:
1. They have the right to contribute the code.
2. They license their contribution to the project under PolyForm Noncommercial
   **and** grant the maintainer the right to relicense it (including under
   commercial terms).

See [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Branding rules

- Applications using DIS **must display** "Powered by DIS — Defensive
  Integration Shield" (exposed as the `DIS_BRANDING` constant).
- The attribution must remain legible and unaltered in wording.

## Trademark notice

"DIS — Defensive Integration Shield" and the Singra names are trademarks of the
maintainer. The license grants copyright/patent rights to the **software**; it
does **not** grant trademark rights. You may not use the names or marks to imply
endorsement, or for a fork/derivative, without written permission. Nominative
use ("compatible with DIS") is allowed.

## Risks for future commercial use

- **R-L1:** Noncommercial-only deters some OSS contributors. Accepted — fits the
  product strategy.
- **R-L2:** PolyForm is not OSI-approved, so DIS is not "Open Source" in the
  strict trademark sense; we label it "source-available". Accepted.
- **R-L3:** Without a CLA, accepted external contributions could block
  relicensing. Mitigated by the mandatory CLA.
