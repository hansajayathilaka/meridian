<!-- Written by /start-review-phase to docs/tasks/phase-N/review-report.md.
     /plan-review-phase reads this and turns each actionable finding into a numbered fix-task. -->
> **Nav:** [tracker](../README.md) · [phase](./README.md) · [Definition of Done](../../../CONTRIBUTING.md)

# Phase N — Review Report

**Reviews:** <build phase(s) / task range covered> · **Date:** <YYYY-MM-DD> · **Reviewers:** code-reviewer, security-reviewer, architect, test-engineer

## Summary
<One paragraph: overall health, headline risks, whether anything blocks the next build phase.>

## Findings
Severity: **blocking** (must fix before next build) · **should-fix** (fix this review phase) · **nit** (optional).

| # | Severity | Area / file | Finding | Recommended fix | → Fix-task |
|---|----------|-------------|---------|-----------------|-----------|
| F1 | blocking | apps/<crate>/<file>:<line> | <what's wrong> | <how to fix> | N.1 |
| F2 | should-fix | … | … | … | N.2 |

## On-the-fly decisions to ratify
<Decisions made during earlier build phases that were never recorded. Architectural ones → `/adr`.>

## Coverage / test gaps
<Missing unit/property/adversarial/conformance coverage found during the sweep.>

## Verdict
<Green to proceed after fix-tasks / blocked until F# resolved.>
