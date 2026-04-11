# Ops Security Testing Pattern

- Keep registration expectations in `RegistrationTest`.
- Keep install-step behavior in `tests/Unit/Install/InstallStepsTest.php`.
- Keep manager and refresh behavior in feature tests.
- Keep doctor posture checks and page rendering in their dedicated tests.
- Run `composer test:ops-security` from `/home/yezz/Developement/packages/1-dev-test` when available in the shared runner.
