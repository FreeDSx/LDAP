Password Policy
================

* [Overview](#overview)
* [Enabling Password Policy](#enabling-password-policy)
* [Defining a Policy](#defining-a-policy)
    * [In Memory](#in-memory)
    * [In the Directory](#in-the-directory)
    * [Policy Resolution Order](#policy-resolution-order)
* [Enforced Behaviours](#enforced-behaviours)
    * [Quality](#quality)
    * [History](#history)
    * [Minimum Age](#minimum-age)
    * [Safe Modify](#safe-modify)
    * [Self-Service Changes](#self-service-changes)
    * [Expiration, Warnings, and Grace Logins](#expiration-warnings-and-grace-logins)
    * [Account Lockout](#account-lockout)
    * [Idle Lockout](#idle-lockout)
    * [Change After Reset](#change-after-reset)
    * [Validity Window](#validity-window)
* [Custom Quality Checker](#custom-quality-checker)
* [Client Side](#client-side)
* [Operational Attributes](#operational-attributes)
* [Not Yet Enforced / Limitations](#not-yet-enforced--limitations)

## Overview

The server implements the password policy described in `draft-behera-ldap-password-policy-10`. When enabled it
enforces policy across four paths:

- **Simple bind** — account lockout, expiration, grace logins, the validity window, and the change-after-reset flag.
- **SASL bind** — the same bind-time checks, applied once the identity is resolved.
- **RFC 3062 Password Modify** — quality, history, minimum age, safe-modify, and self-service rules on the new password.
- **Plain `ldapmodify` of `userPassword`** — the same change-time rules as the Password Modify extended operation.

Policy is **opt-in**: nothing is enforced until a policy source is configured.

## Enabling Password Policy

Configure a policy on `ServerOptions`, either in memory or by pointing at a policy entry in the directory:

```php
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Server\Config\PasswordConfig;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;

$passwordConfig = (new PasswordConfig())
    ->setPolicy(new PasswordPolicy(
        quality: new PasswordQualityRules(minLength: 8),
        lockout: new PasswordLockoutRules(
            enabled: true,
            duration: 300,
            maxFailure: 5,
        ),
    ));

$ldap = new LdapServer(new ServerOptions(passwordConfig: $passwordConfig));
```

Password policy is active when either `setPolicy()` or `setDefaultPolicyDn()` has been set on the `PasswordConfig`.
When active, the policy schema (the `pwdPolicy` auxiliary class and the
`pwd*` attribute types) is merged into the server schema automatically.

## Defining a Policy

### In Memory

A `PasswordPolicy` is composed of four rule groups and can be composed directly in code and set in the server options.
Every field is nullable. A `null` field means "unspecified" and is treated as "no limit".

```php
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordExpirationRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;

$policy = new PasswordPolicy(
    pwdAttribute: 'userPassword',
    quality: new PasswordQualityRules(
        minLength: 8,
        maxLength: 128,
        inHistory: 5,
        checkQuality: 1,
    ),
    change: new PasswordChangeRules(
        minAge: 3600,
        mustChange: true,
        allowUserChange: true,
        safeModify: true,
    ),
    expiration: new PasswordExpirationRules(
        maxAge: 7776000,
        expireWarning: 604800,
        graceAuthnLimit: 3,
    ),
    lockout: new PasswordLockoutRules(
        enabled: true,
        duration: 300,
        maxFailure: 5,
        failureCountInterval: 900,
    ),
);
```

**Note**: All durations are in seconds.

### In the Directory

A policy can instead live in the DIT as an entry carrying the `pwdPolicy` object class. The only required attribute
is `pwdAttribute`:

```ldif
dn: cn=default,ou=policies,dc=example,dc=com
objectClass: top
objectClass: device
objectClass: pwdPolicy
cn: default
pwdAttribute: userPassword
pwdMinLength: 8
pwdInHistory: 5
pwdMaxAge: 7776000
pwdExpireWarning: 604800
pwdGraceAuthNLimit: 3
pwdLockout: TRUE
pwdMaxFailure: 5
pwdLockoutDuration: 300
pwdFailureCountInterval: 900
pwdMustChange: TRUE
pwdSafeModify: TRUE
```

Register it as the default:

```php
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Config\PasswordConfig;
use FreeDSx\Ldap\ServerOptions;

$passwordConfig = (new PasswordConfig())
    ->setDefaultPolicyDn(new Dn('cn=default,ou=policies,dc=example,dc=com'));

$options = new ServerOptions(passwordConfig: $passwordConfig);
```

Per-user policies are supported by setting `pwdPolicySubentry` on the user entry to the DN of a `pwdPolicy` entry.

### Subtree-Scoped Policies

A policy can govern a branch of the directory rather than one entry at a time. Add a subentry that carries both
the `subentry` and `pwdPolicy` object classes directly below an administrative point, and its `subtreeSpecification`
decides which entries it applies to:

```ldif
dn: ou=secure,dc=example,dc=com
objectClass: organizationalUnit
ou: secure
administrativeRole: 2.5.23.4

dn: cn=policy,ou=secure,dc=example,dc=com
objectClass: subentry
objectClass: pwdPolicy
cn: policy
subtreeSpecification: { specificExclusions { chopBefore:"ou=contractors" } }
pwdAttribute: userPassword
pwdLockout: TRUE
pwdMaxFailure: 3
```

Every entry under `ou=secure` is then governed by that policy, except the `ou=contractors` branch the specification
chops out. See the subtree specification grammar in RFC 3672 for the full set of components.

Subentries are not returned by ordinary searches. Read one back with a base scope search on its DN, or use the
subentries control.

### Policy Resolution Order

For a given user the governing policy is resolved as:

1. The `pwdPolicy` entry named by the user's `pwdPolicySubentry` (if present).
2. The nearest governing `pwdPolicy` subentry whose `subtreeSpecification` covers the user.
3. The default DN from `PasswordConfig::setDefaultPolicyDn()` (if configured).
4. The in-memory policy from `PasswordConfig::setPolicy()` (if configured).

If none apply, then no policy is enforced for the user.

## Enforced Behaviours

When a check denies an operation, the server returns the appropriate LDAP result code and (when applicable) a
[password policy response control](#client-side) carrying a `PwdPolicyError` code.

### Quality

`pwdMinLength` and `pwdMaxLength` are enforced by the built-in checker (lengths are measured in characters, not bytes).
`pwdCheckQuality` controls how strictly quality is applied:

- `0`: Quality checking is disabled.
- `1`: Check the password when it is presented in cleartext. Accept it when it cannot be inspected.
- `2`: Check the password; **reject** it when it cannot be inspected (for example, a pre-hashed value).

A too-short password returns `passwordTooShort`. Other quality failure returns `insufficientPasswordQuality`. Both
map to `CONSTRAINT_VIOLATION`.

### History

With `pwdInHistory` set, the server retains that many superseded values in `pwdHistory` and rejects a new password that
matches any of them, or the current password, with `passwordInHistory` (`CONSTRAINT_VIOLATION`). The value recorded is
the one being replaced, so the window is the current password plus that many previous ones.

### Minimum Age

`pwdMinAge` rejects a change attempted within that many seconds of the last change (`pwdChangedTime`) with
`passwordTooYoung` (`CONSTRAINT_VIOLATION`). An entry that must change its password is exempt, since the reset
restriction would otherwise leave it no permitted operation.

### Safe Modify

When `pwdSafeModify` is `TRUE`, a change must supply the current password. A missing existing password returns
`mustSupplyOldPassword` (`INSUFFICIENT_ACCESS_RIGHTS`). A supplied-but-incorrect one returns `INVALID_CREDENTIALS`.

### Self-Service Changes

When `pwdAllowUserChange` is `FALSE`, a user changing their own password is denied with `passwordModNotAllowed`
(`INSUFFICIENT_ACCESS_RIGHTS`). Administrative changes to another entry are unaffected.

### Expiration, Warnings, and Grace Logins

With `pwdMaxAge` set, a password expires that many seconds after `pwdChangedTime`. On bind:

- Within `pwdExpireWarning` of expiry, the response control reports `timeBeforeExpiration`.
- Once expired, each bind consumes a grace login capped by `pwdGraceAuthNLimit`, and by `pwdGraceExpiry` seconds
  since expiry if set. The control reports `graceAuthNsRemaining`.
- With no grace left, the bind fails `INVALID_CREDENTIALS` with `passwordExpired`.

> A password with no `pwdChangedTime` is treated as non-expiring. The server stamps `pwdChangedTime` on every
> policy-managed change.

### Account Lockout

When `pwdLockout` is `TRUE`, each failed bind is recorded in `pwdFailureTime`. Reaching `pwdMaxFailure` failures locks
the account by setting `pwdAccountLockedTime`. `pwdFailureCountInterval`, when set, only counts failures within that
recent window.

`pwdLockoutDuration` controls how long a lock lasts:

- `0` (or unset): the account stays locked until an administrator clears `pwdAccountLockedTime`, or a later successful
  bind clears it.
- A positive value: the lock expires after that many seconds. The next bind attempt clears the stale lock. Failures
  then accumulate again and can re-lock the account.

A locked bind returns `INVALID_CREDENTIALS` with the `accountLocked` error.

In a replicated setup, lockout can apply across the whole cluster so failures against a replica count too. See
[Password Policy](Replication.md#password-policy) under Replication.

### Failed Bind Delay

When both `pwdMinDelay` and `pwdMaxDelay` are set to positive values, the server delays the response to a failed
bind to slow brute-force attempts. The delay starts at `pwdMinDelay` seconds on the first consecutive failure and
doubles with each subsequent failure, capped at `pwdMaxDelay`.

Note: Either value unset or `0` disables the delay (the default).

### Idle Lockout

When `pwdMaxIdle` is set, an account with no successful bind within that many seconds is locked, returning
`INVALID_CREDENTIALS` with `accountLocked`. Idleness is measured from `pwdLastSuccess` (stamped on each successful
bind), falling back to `pwdChangedTime` when no successful bind has been recorded yet.

### Change After Reset

When `pwdMustChange` is `TRUE` and an administrator changes another user's password, the server sets `pwdReset`. At the
user's next bind the response control reports `changeAfterReset`, and the session is restricted to bind, unbind,
StartTLS, the RFC 3062 Password Modify, and a modify of the user's own password. Any other operation is rejected
`INSUFFICIENT_ACCESS_RIGHTS` with `changeAfterReset` until the password is changed. A successful self-change clears
`pwdReset` and lifts the restriction without a rebind.

StartTLS is permitted so a client that bound in the clear can protect the connection before changing its password.

Both flags are required, so an entry marked `pwdReset` is only held to a change while `pwdMustChange` is `TRUE`.
Clearing the policy flag releases entries already marked, and leaving it unset turns the feature off entirely: nothing
sets `pwdReset` and nothing enforces it.

### Validity Window

`pwdStartTime` and `pwdEndTime` on a user entry bound the period the password may be used to authenticate. A bind before
`pwdStartTime` or after `pwdEndTime` fails with `INVALID_CREDENTIALS` (the latter also reports `passwordExpired`).

## Custom Quality Checker

To enforce composition or strength rules beyond length, implement `PasswordQualityCheckerInterface` and register it.
The checker receives the cleartext password and the active `PasswordQualityRules`, and returns a `PwdPolicyError` code
to deny, or `null` to accept:

```php
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\PasswordQualityCheckerInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use SensitiveParameter;

final class ContainsDigitChecker implements PasswordQualityCheckerInterface
{
    public function check(
        #[SensitiveParameter]
        string $plain,
        PasswordQualityRules $rules,
    ): ?int {
        return preg_match('/\d/', $plain) === 1
            ? null
            : PwdPolicyError::INSUFFICIENT_PASSWORD_QUALITY;
    }
}

$passwordConfig = (new PasswordConfig())
    ->setQualityChecker(new ContainsDigitChecker());

$options = new ServerOptions(passwordConfig: $passwordConfig);
```

The default checker (`DefaultPasswordQualityChecker`) enforces `pwdMinLength` / `pwdMaxLength` and honours
`pwdCheckQuality`.

## Client Side

A client requests policy feedback by attaching the password policy request control to a bind, modify, or password
modify request:

```php
use FreeDSx\Ldap\Controls;

$response = $ldap->bind('cn=user,dc=example,dc=com', 'secret', Controls::pwdPolicy());
```

Read the response control to surface warnings and errors:

```php
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;

$control = $response->controls()->get(Control::OID_PWD_POLICY);

if ($control instanceof PwdPolicyResponseControl) {
    $secondsLeft = $control->getTimeBeforeExpiration();
    $graceLeft = $control->getGraceAttemptsRemaining();
    $error = $control->getError();
}
```

`getError()` returns one of the `PwdPolicyError` constants: `PASSWORD_EXPIRED`, `ACCOUNT_LOCKED`, `CHANGE_AFTER_RESET`,
`PASSWORD_MOD_NOT_ALLOWED`, `MUST_SUPPLY_OLD_PASSWORD`, `INSUFFICIENT_PASSWORD_QUALITY`, `PASSWORD_TOO_SHORT`,
`PASSWORD_TOO_YOUNG`, or `PASSWORD_IN_HISTORY`.

## Operational Attributes

The server manages these attributes on user entries; they are written with system privileges and should not be set by
clients:

| Attribute              | Purpose                                                          |
|------------------------|------------------------------------------------------------------|
| `pwdChangedTime`       | Time of the last password change; drives age and expiration.     |
| `pwdFailureTime`       | Timestamps of recent failed binds.                               |
| `pwdAccountLockedTime` | Time the account was locked.                                     |
| `pwdHistory`           | Previous password values retained for `pwdInHistory`.            |
| `pwdGraceUseTime`      | Timestamps of grace logins used after expiration.                |
| `pwdLastSuccess`       | Time of the last successful bind.                                |
| `pwdReset`             | Set when an administrative reset requires a change at next bind. |

`pwdPolicySubentry`, `pwdStartTime`, and `pwdEndTime` are read from the user entry but managed by the operator.

## Not Yet Enforced / Limitations

- Policy is assumed to apply to `userPassword`. Custom password attributes are not supported.
- A plain `ldapmodify` stores the submitted value verbatim. Pre-hashed value cannot be inspected.
- The password policy response control is returned whenever there is something to report, regardless of whether the
  client sent the request control.
