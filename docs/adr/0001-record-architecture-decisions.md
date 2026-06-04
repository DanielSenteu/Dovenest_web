# 1. Record architecture decisions

Date: 2026-06-02

## Status

Accepted

## Context

The codebase has grown organically (static pages + a quote server) and has
accumulated architectural debt and implicit conventions (see `CONTEXT.md`). We
want a lightweight, durable record of significant decisions so future changes —
by humans or AI agents — don't silently undo load-bearing choices.

## Decision

We will use Architecture Decision Records (ADRs), one Markdown file per decision
in `docs/adr/`, numbered sequentially (`NNNN-title.md`). Each ADR states its
Status, Context, Decision and Consequences. The `improve-codebase-architecture`
skill reads this directory.

## Consequences

- Decisions are discoverable and reviewable in version control.
- Rejecting an architectural suggestion for a load-bearing reason should be
  captured as an ADR rather than lost in chat history.
