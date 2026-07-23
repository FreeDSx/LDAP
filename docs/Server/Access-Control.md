Access Control
================

* [Overview](#overview)
* [Default Behaviour: Secure Default](#default-behaviour-secure-default)
    * [Administrators](#administrators)
    * [Manager (Break-Glass Super-User)](#manager-break-glass-super-user)
* [Rule-Based Access Control](#rule-based-access-control)
    * [Rule Evaluation Order](#rule-evaluation-order)
    * [Default Effect](#default-effect)
* [Subject Reference](#subject-reference)
* [Target Reference](#target-reference)
* [Attribute Rules](#attribute-rules)
* [Control Rules](#control-rules)
* [Extended Operation Rules](#extended-operation-rules)
* [Custom Access Control](#custom-access-control)

## Overview

Access control operates at four levels:

- **Operation level**: Checked before each operation executes. Denial sends `INSUFFICIENT_ACCESS_RIGHTS` to the
  client. Covers the following operations: Search, Add, Modify, Delete, ModifyDn, Compare, and PasswordModify.
- **Attribute level**: Checked for each attribute involved in Compare, Add, and Modify operations. Also applied to
  each Search result entry. Disallowed attributes are stripped before the entry is sent. If the entry itself is
  denied at operation level, it is suppressed entirely from results.
- **Control level**: Checked for privileged request controls (Relax Rules by default, configurable via
  `ServerOptions::setPrivilegedControls()`). See [Control Rules](#control-rules).
- **Extended operation level**: Checked for privileged extended operations, configurable via
  `ServerOptions::setPrivilegedExtendedOps()`. See [Extended Operation Rules](#extended-operation-rules).

Rules are bundled in an `AclRules` object configured via `ServerOptions::setAclRules()`. See
[Configuration](Configuration.md).

Bind, WhoAmI, and StartTLS are handled before access control and are always permitted.

## Default Behaviour: Secure Default

With no access control configured, the server applies a secure default (`AclRules::secureDefault()`). It configures:

- Anonymous clients are denied.
- Authenticated clients may perform general operations.
- `userPassword` can be changed only by the entry owner and the administrator, and is never returned in search results.
- Password Modify (RFC 3062) is limited to self and the administrator.
- Privileged controls and extended operations are limited to the administrator.

To keep this protection and add your own rules, start from the secure default and compose on top with the `with*`
methods. This is the recommended way to extend access control, for example to grant a privileged control:

```php
AclRules::secureDefault()
    ->withControlRules(ControlRule::allow(
        Subject::dn('cn=replica,dc=example,dc=com'),
        Target::subtree('dc=example,dc=com'),
        Control::OID_SYNC_REQUEST,
    ));
```

Building from `new AclRules()` instead gives a blank policy with no credential protection, so a `userPassword` rule is
then yours to add. Composing on `secureDefault()` is the safe default. To apply just the credential protection to a
policy you build from scratch, use `AclRules::withCredentialProtection()`:

```php
(new AclRules())
    ->withOperationRules(/* your rules */)
    ->withCredentialProtection(Subject::group('cn=admins,ou=groups,dc=example,dc=com'));
```

### Administrators

`setAdministrators()` designates a directory administrator that the secure default grants password-reset and
privileged-operation rights. Point it at a DN or a group.

```php
$options->setAdministrators(Subject::dn('uid=admin,ou=people,dc=example,dc=com'));
$options->setAdministrators(Subject::group('cn=admins,ou=groups,dc=example,dc=com'));
```

Group membership is read from the group entry in the directory. With no administrator set, only self-service password
change works. Administrative resets then require a [manager](#manager-break-glass-super-user).

### Manager (Break-Glass Super-User)

`setManager()` configures an optional super-user that is not a directory entry. It is recognized at bind, bypasses
access control, and is exempt from password-policy lockout. The password is stored hashed and rotated through config.

```php
$options->setManager(new ManagerIdentity(
    new Dn('cn=manager'),
    '{SSHA}...hashed password...',
));
```

There is no default manager, and no name or password ships. Use it for recovery, not routine administration. On a
read-only replica it bypasses access control for reads, but writes are still referred to the provider.

## Rule-Based Access Control

Bundle operation, attribute, and control rules in an `AclRules` object and set it on `ServerOptions`. Rules are
evaluated in definition order (first match wins). If no rule matches, a configurable default effect applies (deny by
default). `AclRules` is immutable; the `with*` methods are variadic and return a new instance.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;

$server = new LdapServer(
    (new ServerOptions())
        ->setAclRules(
            (new AclRules())
                ->withOperationRules(
                    // Admin group can do anything.
                    OperationRule::allow(
                        Subject::group('cn=admins,dc=example,dc=com'),
                    ),
                    // Authenticated users can search and compare.
                    OperationRule::allow(
                        Subject::authenticated(),
                        Target::any(),
                        OperationType::Search,
                        OperationType::Compare,
                    ),
                    // Users can modify their own entry.
                    OperationRule::allow(
                        Subject::self(),
                        Target::any(),
                        OperationType::Modify,
                    ),
                    // Deny everything else.
                    OperationRule::deny(Subject::anyone()),
                )
                ->withAttributeRules(
                    // Users can see their own userPassword.
                    AttributeRule::allow(
                        Subject::self(),
                        Target::any(),
                        'userPassword',
                    ),
                    // Hide userPassword from everyone else.
                    AttributeRule::deny(
                        Subject::anyone(),
                        Target::any(),
                        'userPassword',
                    ),
                ),
        )
        ->setStorageConfig(PdoConfig::forSqlite('/var/lib/myapp/ldap.sqlite'))
);
```

### Rule Evaluation Order

Rules are evaluated in definition order. For each rule:

| Check          | Passes when…                                                           | On fail                                                             |
|----------------|------------------------------------------------------------------------|---------------------------------------------------------------------|
| Operation type | Rule has no operations listed, **or** current operation is in the list | Skip to next rule                                                   |
| Target DN      | Target matcher returns true for the entry DN                           | Skip to next rule                                                   |
| Subject        | Subject matcher returns true for the bound user                        | Skip to next rule                                                   |
| Effect         | —                                                                      | `Allow` → permit; `Deny` → reject with `INSUFFICIENT_ACCESS_RIGHTS` |

If no rule matches, the [default effect](#default-effect) is applied.

For attribute rules the same logic applies per attribute. Any attribute that matches no rule is kept (default allow).

### Default Effect

When no operation rule matches, `AclRules::$defaultOperationEffect` determines the outcome (default: `Effect::Deny`).
Control rules have their own `$defaultControlEffect`, also `Effect::Deny`. Privileged controls are off unless granted.

```php
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;

// Allow everything not explicitly matched (open policy).
(new ServerOptions())->setAclRules(
    new AclRules(defaultOperationEffect: Effect::Allow),
);
```

## Subject Reference

Use the `Subject` factory to build subject matchers.

| Factory method                                                                                       | Matches                                                               |
|------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------|
| `Subject::anyone()`                                                                                  | Every client (including anonymous)                                    |
| `Subject::anonymous()`                                                                               | Anonymous (unbound) clients only                                      |
| `Subject::authenticated()`                                                                           | Any successfully bound client                                         |
| `Subject::self()`                                                                                    | A client whose bound DN equals the target entry DN (case-insensitive) |
| `Subject::dn(string $dn)`                                                                            | A client bound as the specific DN (case-insensitive)                  |
| `Subject::dnSubtree(string $dn)`                                                                     | A client whose bound DN is within the given subtree                   |
| `Subject::group(string $groupDn, string $memberAttribute = 'member', int $maxCacheSize = 200)` | A client whose bound DN appears in the group entry's member attribute |
| `Subject::callback(Closure $fn)`                                                                     | Delegates to `fn(TokenInterface $token, Dn $targetDn): bool`          |

**Group membership caching**: `Subject::group()` fetches the group entry once per connection. The cache size is
controlled by `$maxCacheSize` (default: 200, FIFO; 0 to disable cache). Membership changes made after the first evaluation for a
given connection are not visible until the client reconnects.

**Group rename**: If a referenced group entry is renamed or deleted, the rule fails closed (access denied). Protect
ACL group entries with their own rules to prevent unauthorized `ModifyDn` on them:

```php
// Prevent non-admins from renaming entries under ou=groups.
OperationRule::deny(
    Subject::authenticated(),
    Target::subtree('ou=groups,dc=example,dc=com'),
    OperationType::ModifyDn,
),
```

## Target Reference

Use the `Target` factory to build target matchers.

| Factory method                | Matches                                 |
|-------------------------------|-----------------------------------------|
| `Target::any()`               | Every entry DN                          |
| `Target::dn(string $dn)`      | The specific DN only (case-insensitive) |
| `Target::subtree(string $dn)` | The given DN and all entries beneath it |

## Attribute Rules

`AttributeRule` follows the same subject/target/first-match-wins structure as operation rules. An empty attribute list
matches all attributes.

Attribute rules are enforced in three places:

- **Search**: denied attributes are stripped from each result entry before it is sent. If the bound user is denied
  the Search operation on an entry's DN, the entry is suppressed entirely (not sent at all).
- **Compare**: a Compare request is rejected if the bound user is denied access to the compared attribute.
- **Add / Modify**: the request is rejected if the bound user is denied access to any attribute being written.

```php
(new AclRules())->withAttributeRules(
    // Only admins can see or write userPassword.
    AttributeRule::allow(
        Subject::group('cn=admins,dc=example,dc=com'),
        Target::any(),
        'userPassword',
    ),
    AttributeRule::deny(
        Subject::anyone(),
        Target::any(),
        'userPassword',
    ),
    // Strip all attributes from ou=internal entries for non-admins (only DN returned).
    AttributeRule::deny(
        Subject::authenticated(),
        Target::subtree('ou=internal,dc=example,dc=com'),
    ),
)
```

## Control Rules

Privileged request controls are gated per identity with `ControlRule`s (same subject/target/first-match-wins structure,
keyed on control OID; empty OID list matches all). They are **denied by default**. A control does nothing unless a
rule grants it. `SimpleAccessControl` denies all controls, so this requires `RuleBasedAccessControl`.

The gated controls are:

* Relax Rules control** (`Control::OID_RELAX_RULES`). With it, an authorized client (see [Schema Validation](Schema.md#validation-mode)).

This set defaults to the Relax Rules control and is configurable with `ServerOptions::setPrivilegedControls()`. For
example, add `Control::OID_SUBTREE_DELETE` to gate the Tree-Delete control the same way. See
[Configuration](Configuration.md#setprivilegedcontrols).

```php
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;

// Only the admin group may relax schema constraints, and only under ou=migrate.
(new AclRules())->withControlRules(
    ControlRule::allow(
        Subject::group('cn=admins,dc=example,dc=com'),
        Target::subtree('ou=migrate,dc=example,dc=com'),
        Control::OID_RELAX_RULES,
    ),
);
```

A client attaches the control with `Controls::relaxRules()`, e.g. `$client->create($entry, Controls::relaxRules())`.

## Extended Operation Rules

Privileged extended operations are gated per identity with `ExtendedOperationRule`s, keyed on the request OID (empty OID
list matches all). They are denied by default. The set of gated OIDs is configured with
`ServerOptions::setPrivilegedExtendedOps()`.

```php
use FreeDSx\Ldap\Server\AccessControl\Rule\ExtendedOperationRule;

(new AclRules())->withExtendedOperationRules(
    ExtendedOperationRule::allow(
        Subject::group('cn=admins,ou=groups,dc=example,dc=com'),
        '1.3.6.1.4.1....',
    ),
);
```

## Custom Access Control

For cases where the built-in rule system is insufficient, implement `AccessControlInterface` and pass it via
`LdapServer::useAccessControl()`:

```php
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\Token\TokenInterface;

class MyAccessControl implements AccessControlInterface
{
    public function authorizeOperation(
        OperationType $operation,
        TokenInterface $token,
        Dn $dn,
    ): void {
        if (!$this->isAllowed($operation, $token, $dn)) {
            throw new OperationException(
                'Access denied.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            );
        }
    }

    public function authorizeAttribute(
        TokenInterface $token,
        Dn $dn,
        string $attribute,
        AttributeAccess $access,
    ): void {
        // Throw OperationException to deny access to the attribute.
    }

    public function authorizeControl(
        TokenInterface $token,
        Dn $dn,
        string $controlOid,
    ): void {
        // Throw OperationException to deny use of a privileged control.
    }

    public function authorizeExtendedOperation(
        TokenInterface $token,
        string $oid,
    ): void {
        // Throw OperationException to deny use of a privileged extended operation.
    }

    /**
     * Return null to suppress the entry from search results entirely.
     */
    public function filterEntry(
        TokenInterface $token,
        Entry $entry,
    ): ?Entry {
        return $entry;
    }
}

$server->useAccessControl(new MyAccessControl());
```
