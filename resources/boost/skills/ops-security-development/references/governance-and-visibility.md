# Governance And Visibility Rules

- Keep security requests and requirements normalized through foundation registries.
- Keep `DatabaseSecurityRequestBroker` as the package-owned broker for persisted visibility rows.
- Keep payload preview fields explicit and masked where required.
- Keep `SecurityDecisionResolver` and `SecurityPayloadSanitizer` aligned with current governance rules.
- Treat producer packages such as ops, access, and other security-aware packages as contributors, not as hidden runtime dependencies.
