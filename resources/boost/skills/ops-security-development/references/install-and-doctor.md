# Install And Doctor Rules

Declared install steps:

- `VerifyOpenSslExtensionStep`
- `VerifyOpsDependencyStep`
- `EnsureOpsSecurityVisibilityStoreReadyInstallStep`
- `PublishSecurityConfigStep`

Declared doctor checks:

- `SslPostureCheck`
- `SshPostureCheck`
- `SecretHealthCheck`
- `SecurityConfigCheck`
- `SecurityResolverCheck`
- `LoginThrottleCheck`
- `PasswordConfirmationCheck`
- `PrivilegedMfaCheck`
- `SecurityDriftCheck`
- `SecurityPolicyConflictCheck`

Keep doctor checks diagnostic-only and keep install steps explicit about dependency and storage prerequisites.
