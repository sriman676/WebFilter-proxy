---
description: Verify a phase gate and tag it
argument-hint: <phase number 0-13>
---
Verify the Phase $ARGUMENTS gate checklist in docs/phases/PHASE-$ARGUMENTS.md (and the loop in docs/BUILD_PLAN.md): build, fmt, clippy, tests, coverage gates, all PT cases
executed and passing, zero open Critical/High findings, docs and CHANGELOG updated. If everything passes run
`git tag phase-$ARGUMENTS-complete` (plus the milestone tag if the brief says so) and update docs/STATE.md; otherwise list exactly what fails and fix it. Output a short gate report.
