# onboarding stack module

- Module id: `onboarding`
- Module repo: `onboarding-stack-module`
- Source repo: none declared
- Lifecycle: `active`

## Owned overlays
- `stack.compose/onboarding.yml`
- `stack.containers/onboarding-service`

## Dependencies
- `stack-foundation`

## Deployed contract

Membership is admin-created only. This module must not expose public invite
signup, self-service registration, or any unauthenticated onboarding entrypoint.

`onboarding.$DOMAIN` exists for users that already exist in Keycloak and still
have required actions to complete. Users marked with `onboarding_required`
should be redirected to the authenticated onboarding page after login.

Tests and screenshots should prove the authenticated required-action flow. A
public registration form or anonymous onboarding path is a regression.

## Validation

```sh
./tests/validate.sh
```

## Lifecycle

`active` modules are expected to keep `stack.module.json`, owned overlays, and `tests/validate.sh` in sync.
