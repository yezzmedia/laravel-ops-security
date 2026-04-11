# Approved V1 Ops Security Surface

- permissions:
  - `ops-security.posture.view`
  - `ops-security.posture.refresh`
- feature:
  - `ops-security`
- audit event:
  - `security-posture-refreshed`
- ops module:
  - `ops-security`
- security requests:
  - `ops-security.request.auth.login-throttle`
  - `ops-security.request.identity.privileged-mfa`
- security requirements:
  - `ops-security.auth.login-throttle`
  - `ops-security.identity.privileged-mfa`

Core public runtime types include:

- `OpsSecurityPlatformPackage`
- `OpsSecurityServiceProvider`
- `OpsSecurityManager`
- `SslPostureResolver`
- `SshPostureResolver`
- `SecretHealthResolver`
- `SecurityConfigResolver`
- `SecurityPostureSummaryBuilder`
- `SecurityPayloadSanitizer`
- `DatabaseSecurityRequestBroker`
- `RefreshSecurityPostureAction`
