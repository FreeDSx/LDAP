Access Control
================

* [Overview](#overview)
* [Default Behaviour: Secure Default](#default-behaviour-secure-default)
    * [Administrators](#administrators)
    * [Manager (Break-Glass Super-User)](#manager-break-glass-super-user)
* [Rule-Based Access Control](#rule-based-access-control)
    * [Rule Evaluation Order](#rule-evaluation-order)
    * [Default Effect](#default-effect)
    * [Grant Helpers](#grant-helpers)
    * [Server-Generated Entries](#server-generated-entries)
    * [Self-Service Attributes](#self-service-attributes)
* [Subject Reference](#subject-reference)
* [Target Reference](#target-reference)
* [Attribute Rules](#attribute-rules)
* [Confidential Attributes](#confidential-attributes)
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
- Authenticated clients may search and compare any entry.
- Writes require a grant. An identity may modify its own entry, limited to a small set of personal attributes.
- Everything else is left to the administrator, when one is configured.
- `userPassword` can be changed only by the entry owner and the administrator, and is never returned in search results.
- Password Modify (RFC 3062) is limited to self and the administrator.
- Privileged controls and extended operations are limited to the administrator.

To keep this protection and add your own rules, start from the secure default and compose on top with the `with*`
methods. This is the recommended way to extend access control, for example to grant a privileged control:

```php
AclRules::secureDefault()
    ->withReplicaGrants(Subject::dn('cn=replica,dc=example,dc=com'));
```

Each category has three setters. Rules are evaluated in order and the first match wins, so the one you pick decides
precedence:

| Setter        | Effect                                                        |
|---------------|---------------------------------------------------------------|
| `append*`     | Adds to the end, so existing rules match first.                |
| `prepend*`    | Adds to the front, so the new rules match first.               |
| `replace*`    | Discards the whole category, including the secure default's.   |

`append*` is what you want when composing on `secureDefault()`:

```php
$rules = AclRules::secureDefault(Subject::group('cn=admins,ou=groups,dc=example,dc=com'));

$rules = $rules->appendControlRules(ControlRule::allow(
    Subject::dn('cn=replica,dc=example,dc=com'),
    Target::subtree('dc=example,dc=com'),
    Control::OID_SYNC_REQUEST,
));
```

A deny only takes effect if it is matched before anything that would allow the same thing, so use `prepend*` for it:

```php
$rules = $rules->prependAttributeRules(
    AttributeRule::deny(
        Subject::anyone(),
        Target::any(),
        'employeeNumber',
    )->forRead(),
);
```

`replace*` drops what the secure default installed, including the `userPassword` protection, so reach for it only
when you are defining a category from scratch.

Building from `AclRules::fromEmpty()` instead gives a blank policy with no credential protection, so a `userPassword`
rule is then yours to add. Composing on `secureDefault()` is the safe default. To apply just the credential protection to a
policy you build from scratch, use `AclRules::withCredentialProtection()`:

```php
AclRules::fromEmpty()
    ->replaceOperationRules(/* your rules */)
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
default). `AclRules` is immutable; every setter is variadic and returns a new instance.

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
            AclRules::fromEmpty()
                ->replaceOperationRules(
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
                ->replaceAttributeRules(
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
| Effect         | Always reached once the checks above pass                              | `Allow` → permit; `Deny` → reject with `INSUFFICIENT_ACCESS_RIGHTS` |

If no rule matches, the [default effect](#default-effect) is applied.

For attribute rules the same logic applies per attribute, but the fallback differs by direction. An attribute write
that matches no rule is denied. An attribute read that matches no rule is kept.

### Default Effect

The defaults are fixed rather than configurable:

- Operations that match no rule are denied.
- Attribute writes that match no rule are denied.
- Attribute reads that match no rule are allowed, so a search still returns attributes you wrote no rule for.
- Controls and extended operations that match no rule are denied, so privileged controls are off unless granted.

Because writes are denied by default, granting an operation is not enough on its own. A rule that allows `Add` or
`Modify` still needs a matching attribute rule for the attributes being written, otherwise the operation is
allowed and then every attribute in it is refused.

```php
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;

OperationRule::allow(
    Subject::group('cn=admins,dc=example,dc=com'),
),
// Without this the operation above is permitted but writes no attributes.
AttributeRule::allow(
    Subject::group('cn=admins,dc=example,dc=com'),
    Target::any(),
)->forWrite(),
```

`withFullAccess()` writes that pair for you. See [Grant Helpers](#grant-helpers).

### Grant Helpers

These methods bundle grants that are awkward to spell out rule by rule. They append to the current rules rather than
replacing them, so they compose on `secureDefault()` or on a policy built from `fromEmpty()`.

| Method                                                    | Grants                                                                            |
|-----------------------------------------------------------|-----------------------------------------------------------------------------------|
| `withFullAccess($subject, $target = new AnyTargetMatcher())`   | Every operation and every attribute write over the target                         |
| `withSelfServiceWrites($attributes = AclRules::SELF_WRITABLE_ATTRIBUTES)` | Modify on an identity's own entry, limited to the given attributes |
| `withCredentialProtection($administrators = null)`        | The `userPassword` and Password Modify rules, plus privileged controls and extended operations for the administrator |
| `withReplicaGrants($replica, $target = new AnyTargetMatcher())` | The content-sync control, the ppolicy-forward extended operation, and confidential attribute reads |

`AclRules::secureDefault()` is built from the first three. `withFullAccess()` is what it applies to the configured
[administrator](#administrators), so reaching for it directly is how you grant a second identity the same rights.

It covers operations and attribute writes only. Controls, extended operations, and confidential attributes are gated
separately, which is why an administrator gets those from `withCredentialProtection()` rather than from this method.

```php
// A provisioning account with full rights over one subtree.
AclRules::secureDefault(Subject::group('cn=admins,ou=groups,dc=example,dc=com'))
    ->withFullAccess(
        Subject::dn('cn=provisioning,dc=example,dc=com'),
        Target::subtree('ou=people,dc=example,dc=com'),
    );
```

Rule order still applies. These helpers append, so a grant added this way is reached only after the rules already in
the set. A `deny` sitting earlier continues to win.

### Server-Generated Entries

Three entries are generated by the server rather than read from storage, and each has its own default:

| Entry | Default | How to change it |
|---|---|---|
| Root DSE (base `""`) | readable by anyone, including anonymous | not deniable, see below |
| Subschema (`cn=Subschema`) | any authenticated identity | `withSubschemaAccess()` |
| `cn=monitor` | the configured administrator only | `withMonitorAccess()` |

`cn=monitor` is restricted by default because it exposes connection counts, operation counts, traffic
volume, the host name and uptime. To open it to every authenticated identity:

```php
AclRules::secureDefault(Subject::group('cn=admins,ou=groups,dc=example,dc=com'))
    ->withMonitorAccess(Subject::authenticated());
```

The subschema entry takes the DN it applies to, since that DN is configurable:

```php
$options->setAclRules(
    $options->getAclRules()->withSubschemaAccess(
        Subject::anyone(),
        $options->getSubschemaEntry(),
    ),
);
```

The Root DSE is never gated. RFC 4513 section 5.2.1.5 has servers let all clients, "even those with an
anonymous authorization", read `supportedSASLMechanisms` before authenticating, and comparing that list
before and after a SASL exchange is how a client detects a downgrade attack. No rule can deny the entry.

Individual attributes on it are still subject to read rules, so a deployment that wants to reduce
fingerprinting can name them:

```php
AttributeRule::deny(
    Subject::anonymous(),
    Target::dn(''),
    'vendorName',
    'vendorVersion',
)->forRead()
```

Do not deny `supportedSaslMechanisms` this way. It is permitted, but it breaks the discovery the RFC
asks servers to support.

### Self-Service Attributes

The secure default lets an identity change a small set of personal attributes on its own entry, listed in
`AclRules::SELF_WRITABLE_ATTRIBUTES`. Attributes carrying authorization, identity, or account recovery are left out,
because self-service on those is a route to privilege escalation or account takeover.

Pass a second argument to `secureDefault()` to change the set without rebuilding the policy. Spread the constant to
keep the defaults and add to them.

```php
// The shipped set, plus one more.
AclRules::secureDefault(
    Subject::group('cn=admins,ou=groups,dc=example,dc=com'),
    [...AclRules::SELF_WRITABLE_ATTRIBUTES, 'preferredLanguage'],
);

// Self-service on nothing but the password, which withCredentialProtection still allows.
AclRules::secureDefault(
    Subject::group('cn=admins,ou=groups,dc=example,dc=com'),
    [],
);
```

Widen the set with care. Granting `member` or `memberOf` lets an identity add itself to a group, and granting
`objectClass` lets it change which attributes its own entry may hold.

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
| `Subject::group(string $groupDn, string $memberAttribute = 'member', int $cacheTtl = 5)`             | A client whose bound DN appears in the group entry's member attribute |
| `Subject::callback(Closure $fn)`                                                                     | Delegates to `fn(TokenInterface $token, Dn $targetDn): bool`          |

**Group membership caching**: `Subject::group()` re-reads the group entry at most once per `$cacheTtl` seconds
(default: 5, or 0 to read every time). Membership is checked for every entry a search returns, so reading it each
time would mean one backend read per entry.

The cache lifetime is also the revocation window: removing someone from a group takes effect within `$cacheTtl`
seconds rather than immediately.

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
AclRules::fromEmpty()->replaceAttributeRules(
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

## Confidential Attributes

An attribute the schema marks `X-CONFIDENTIAL` is withheld from anyone without an explicit grant, both in results and
in search filters. `userPassword` ships this way, so out of the box it is writable by its owner and readable by no one.

A withheld attribute behaves as though it is not present on the entry. Filtering on one matches nothing, and it never
appears in a result:

```
(userPassword=x)                -> no entries
(&(cn=alice)(userPassword=x))   -> no entries
(|(cn=alice)(userPassword=x))   -> the cn=alice branch still matches
```

Access is granted with a subject-only rule:

```php
AclRules::fromEmpty()->replaceConfidentialAccess(
    // Named attributes, or ConfidentialAccessRule::allowAny() for every confidential attribute.
    ConfidentialAccessRule::allow(
        Subject::group('cn=admins,dc=example,dc=com'),
        'userPassword',
    ),
)
```

Mark your own attributes confidential with the extension:

```php
new AttributeType(
    '1.3.6.1.4.1.99999.1.1',
    ['secretCode'],
    equalityOid: MatchingRuleOid::OID_CASE_EXACT_MATCH,
    syntaxOid: SyntaxOid::OID_DIRECTORY_STRING,
    extensions: [AttributeType::EXTENSION_CONFIDENTIAL => [AttributeType::EXTENSION_ENABLED_VALUE]],
)
```

Four things to keep in mind:

- A grant is required in addition to read access. A permissive `AttributeRule` cannot re-expose a confidential
  attribute.
- Administrators are locked out too until granted. Only the break-glass manager bypasses this.
- Writes are unaffected, which is what keeps `userPassword` settable by its owner while unreadable.
- A custom schema must carry the extension. Supplying your own `userPassword` definition through
  a schema source without it silently drops the protection.

A replica needs to read confidential attributes in order to replicate them, so `AclRules::withReplicaGrants()`
includes that grant along with the sync control.

## Control Rules

Privileged request controls are gated per identity with `ControlRule`s (same subject/target/first-match-wins structure,
keyed on control OID; empty OID list matches all). They are **denied by default**. A control does nothing unless a
rule grants it.

The gated controls are:

* Relax Rules control** (`Control::OID_RELAX_RULES`). With it, an authorized client (see [Schema Validation](Schema.md#validation-mode)).

This set defaults to the Relax Rules control and is configurable with `ServerOptions::setPrivilegedControls()`. For
example, add `Control::OID_SUBTREE_DELETE` to gate the Tree-Delete control the same way. See
[Configuration](Configuration.md#setprivilegedcontrols).

```php
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;

// Only the admin group may relax schema constraints, and only under ou=migrate.
AclRules::fromEmpty()->replaceControlRules(
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

AclRules::fromEmpty()->replaceExtendedOperationRules(
    ExtendedOperationRule::allow(
        Subject::group('cn=admins,ou=groups,dc=example,dc=com'),
        '1.3.6.1.4.1....',
    ),
);
```

## Custom Access Control

For cases where the built-in rule system is insufficient, implement `AccessControlInterface` and pass it via
`ServerOptions::setAccessControl()`:

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

    /**
     * Return false to withhold an attribute the schema marks X-CONFIDENTIAL.
     */
    public function hasConfidentialAccess(
        TokenInterface $token,
        string $attribute,
    ): bool {
        return false;
    }
}

$options->setAccessControl(new MyAccessControl());
```
