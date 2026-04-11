---
name: ops-security-development
description: "Build and maintain yezzmedia/laravel-ops-security. Activate when changing security posture resolvers, governance request or requirement visibility, security install or doctor flows, ops security page behavior, audit integration, or package tests that depend on the approved security V1 surface."
license: MIT
metadata:
  author: yezzmedia
---

# Ops Security Development

## Documentation

Use `search-docs` for Laravel, Filament, Pest, Package Tools, and Boost details. Use the reference files in this skill for the approved security runtime surface.

Use the `foundation-package-development` skill when descriptor capability choices or foundation registration behavior change.

## When To Use This Skill

Activate this skill when working inside `yezzmedia/laravel-ops-security`, especially when changing:

- SSL, SSH, secret, or security-config posture resolvers
- security request or requirement visibility flows
- security posture summarization, visibility storage, or sanitization
- install steps, doctor checks, or audit integration
- the security posture page or package tests that prove the real runtime surface

## Core Rules

- Keep governance visibility separate from the underlying producer implementations.
- Keep posture resolvers focused on observation and reporting, not hidden mutation.
- Keep security request and requirement handling normalized through foundation registries.
- Keep sensitive payloads sanitized and preview-safe.
- Keep audit integration optional and package-config driven.
- Keep package install checks diagnostic and explicit.

## References

- Use [references/runtime-surface.md](references/runtime-surface.md) for the approved security package surface.
- Use [references/install-and-doctor.md](references/install-and-doctor.md) for install-step and doctor-check boundaries.
- Use [references/governance-and-visibility.md](references/governance-and-visibility.md) for request, requirement, broker, and sanitizer rules.
- Use [references/filament-surface.md](references/filament-surface.md) for the operator page surface.
- Use [references/testing.md](references/testing.md) for verification expectations.
- Use [references/checklist.md](references/checklist.md) before finalizing security changes.

## Common Pitfalls

- mixing governance visibility with ownership of Fortify, auth, or passkey runtimes
- bypassing the payload sanitizer for request previews
- changing install or doctor flows without keeping the package descriptor aligned
- turning posture resolvers into hidden repair routines
- proving behavior only through host integration instead of package tests
