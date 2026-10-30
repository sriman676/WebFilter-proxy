---
description: Build one phase (progressive reading, tests first, pentest gate)
argument-hint: <phase number 0-13>
---
Read docs/STATE.md and docs/phases/PHASE-$ARGUMENTS.md, plus ONLY the sections/IDs that brief lists (and docs/DECISIONS.md).
Do not ask questions; record new choices in docs/DECISIONS_ADDENDUM.md. Use plan mode, implement tests first/alongside, run
`just fmt lint test`, run `/pentest-phase $ARGUMENTS`, then `/phase-gate $ARGUMENTS`. Update docs/STATE.md and CHANGELOG.md.
Stop at the gate with a summary of 15 lines or fewer.
