---
name: Feature request
about: Propose a change to Axto's behavior or scope
title: ""
labels: enhancement
---

**Problem**

What are you trying to do that Axto doesn't support today?

**Proposed change**

Before proposing new behavior in Axto itself, consider whether this
belongs in the *caller's* claim construction instead — Axto signs
whatever claims it's handed, and most new functionality (new claim
shapes, token types, delegation semantics) can be built entirely on the
caller side without changing Axto's contract. See the "Axto's contract
never changes" principle in the README.

If it genuinely needs a change here, describe it.

**Alternatives considered**
