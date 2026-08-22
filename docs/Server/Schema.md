Schema Validation
=================

* [Default Behavior](#default-behavior)
* [What Gets Validated](#what-gets-validated)
* [Entry Requirements](#entry-requirements)
    * [extensibleObject](#extensibleobject)
* [Validation Mode](#validation-mode)
    * [SchemaConfig:setValidationMode](#schemaconfigsetvalidationmode)
* [Custom Schema](#custom-schema)
    * [SchemaConfig](#schemaconfig)
    * [Adding a Schema](#adding-a-schema)
    * [Custom Sources](#custom-sources)
        * [What Is Not Read](#what-is-not-read)
        * [SchemaLoadMode](#schemaloadmode)
    * [Confidential Attributes](#confidential-attributes)
* [Operational Attributes](#operational-attributes)
* [String Matching and Internationalization (RFC 4518)](#string-matching-and-internationalization-rfc-4518)

Configuring backend storage automatically enables schema validation using the built-in RFC 4519 schema in
`Strict` mode.

## Default Behavior

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(new ServerOptions(
    PdoConfig::forSqlite('/var/lib/myapp/ldap.sqlite'),
));
```

## What Gets Validated

Every `add` and `modify` is checked before reaching storage:

- At least one structural `objectClass` known to the schema is present.
- All `MUST` attributes for the object class chain are present.
- No attributes outside the `MUST` + `MAY` set appear (unless `extensibleObject` is included).
- Single-valued attributes carry at most one value.
- Attributes marked `NO-USER-MODIFICATION` are not writable by clients.

Failures return `objectClassViolation` (65), `undefinedAttributeType` (17), or `constraintViolation` (19)
with a diagnostic message naming the offending attribute or class.

## Entry Requirements

An entry needs a structural `objectClass` the schema recognises and every `MUST` attribute it requires.

```php
use FreeDSx\Ldap\Entry\Entry;

$entry = Entry::fromArray(
    'cn=alice,ou=people,dc=example,dc=com',
    [
        'objectClass' => 'inetOrgPerson',
        'cn'          => 'alice',
        'sn'          => 'Smith',   // MUST for inetOrgPerson
    ],
);
```

### extensibleObject

Adding `extensibleObject` as an auxiliary class lets an entry hold any attribute the schema defines,
whether or not its object classes permit it.

```php
$entry = Entry::fromArray(
    'cn=alice,ou=people,dc=example,dc=com',
    [
        'objectClass' => ['inetOrgPerson', 'extensibleObject'],
        'cn'          => 'alice',
        'sn'          => 'Smith',
        'uidNumber'   => '1001',   // not in inetOrgPerson MAY; allowed via extensibleObject
    ],
);
```

Only the permitted-attribute list is waived. The entry still needs a structural class, still needs every
`MUST` attribute its classes require, and every attribute it holds must be defined by the schema. An
undefined attribute is rejected with `undefinedAttributeType` (17) whether or not `extensibleObject` is
present.

### Carrying an auxiliary class

An auxiliary class such as `pwdPolicy` cannot stand on its own, so pair it with a structural class.
`device` is the conventional carrier:

```php
$entry = Entry::fromArray(
    'cn=default-policy,ou=policies,dc=example,dc=com',
    [
        'objectClass'  => ['top', 'device', 'pwdPolicy'],
        'cn'           => 'default-policy',
        'pwdAttribute' => 'userPassword',
    ],
);
```

## Validation Mode

------------------
#### SchemaConfig:setValidationMode

**Default**: `SchemaValidationMode::Strict`

| Mode      | Behaviour                                                     |
|-----------|---------------------------------------------------------------|
| `Strict`  | Violations are rejected with an LDAP error.                   |
| `Lenient` | Violations are logged, but the write is allowed.              |
| `Off`     | All writes pass through without checks (and without logging). |

`Lenient` logs each relaxed violation as a `schema.violation` event with `validation_mode: lenient` (see
[Server Logging](Logging.md)). Useful for migrations or editing legacy entries a changed schema would
otherwise make unmodifiable.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\Config\SchemaConfig;
use FreeDSx\Ldap\ServerOptions;

$schemaConfig = (new SchemaConfig())
    ->setValidationMode(SchemaValidationMode::Lenient);

$server = new LdapServer(new ServerOptions(schemaConfig: $schemaConfig));
```

Beyond the server-wide mode, an authorized client can relax validation for a *single* Add/Modify with the Relax Rules
control (logged with `validation_mode: relaxed`). It is ACL-gated — see [Control Rules](Access-Control.md#control-rules).

## Custom Schema

------------------
#### SchemaConfig

The schema is declared as an ordered list of sources on a `SchemaConfig`, passed to `ServerOptions`
alongside the other configuration objects. Sources are read once, when the schema is first needed.

**Default**: `[SchemaResource::Core, SchemaResource::Nis, SchemaResource::PasswordPolicy]`

The shipped schemas are the RFC 4519/4512 core, the RFC 2307 NIS definitions, and the password policy
definitions. All three are on by default.

Schema is written in RFC 4512 description strings, which is the form every directory publishes and the form
`.schema` and `.ldif` schema files use. Load those directly rather than transcribing them. Building definitions in
PHP is for adding a handful of your own.

### Adding a Schema

`addSource()` appends to the shipped set, so it does not have to be restated:

```php
use FreeDSx\Ldap\Schema\LdifSchemaSource;
use FreeDSx\Ldap\Server\Config\SchemaConfig;
use FreeDSx\Ldap\ServerOptions;

$schemaConfig = (new SchemaConfig())
    ->addSource(new LdifSchemaSource('/path/to/schema.ldif'));

$options = new ServerOptions(
    $storageConfig,
    schemaConfig: $schemaConfig,
);
```

`ServerOptions::getSchemaConfig()` returns the config in use, so the same can be done without constructing one:

```php
$options = new ServerOptions($storageConfig);

$options->getSchemaConfig()
    ->addSource(new LdifSchemaSource('/path/to/schema.ldif'));
```

To run a minimal directory instead, replace the list outright with `setSources()`:

```php
$schemaConfig = (new SchemaConfig())->setSources(SchemaResource::Core);
```

Sources merge in order, so a later one overrides an earlier one on OID or name collision. Vendor extensions an
overriding definition omits are carried forward, so protections such as `X-CONFIDENTIAL` survive.

### Custom Sources

Schema that comes from somewhere else, such as a database or a generated definition set, is provided by
implementing `SchemaSourceInterface`. It is read at resolve time rather than when it is configured:

```php
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaSourceInterface;

final class DatabaseSchemaSource implements SchemaSourceInterface
{
    public function load(): Schema
    {
        // Build and return a Schema.
    }
}
```

Definitions go on the entry under `attributeTypes`, `objectClasses` and `ldapSyntaxes`:

```
dn: cn=Subschema
ldapSyntaxes: ( 1.3.6.1.4.1.99999.3.1 DESC 'Vendor Syntax' )
attributeTypes: ( 1.3.6.1.4.1.99999.1.1 NAME 'myCustomAttr' EQUALITY 2.5.13.2
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
objectClasses: ( 1.3.6.1.4.1.99999.2.1 NAME 'myCustomClass' SUP top STRUCTURAL
  MUST myCustomAttr )
```

To adopt the schema of an existing directory instead, read its subschema entry with `SubschemaLoader` and
supply the result as a source:

```php
$entry = (new LdapClient())->readOrFail('cn=Subschema', ['+']);

$loaded = (new SubschemaLoader())->fromEntry($entry);
```

The subschema DN varies by vendor (eg. `cn=Subschema` or `cn=schema`). Read it from the Root DSE
`subschemaSubentry` attribute when it is not known ahead of time. A string source is handled by
`fromLdifString()`.

#### What Is Not Read

Matching rules are skipped, since a matching rule carries the comparator that implements it and a description string
cannot express one. A loaded schema uses the comparators of the schema it is merged into.

An attribute keeps its `EQUALITY`, `ORDERING` and `SUBSTR` values even when no rule of that name is registered.
Filters against such an attribute fall back to case-insensitive comparison rather than failing.

------------------
#### SchemaLoadMode

Decides what happens when a definition cannot be parsed, or references something that does not exist.

**Default**: `SchemaLoadMode::Strict`

| Mode | Malformed definition | Unresolved `SUP`, `SYNTAX`, `MUST` or `MAY` |
| --- | --- | --- |
| `Strict` | fails the load | fails the load |
| `Lenient` | skipped | kept as-is |

Strict suits schema you control. A subschema read from another directory often needs `Lenient`, because RFC 4512
§4.2 makes publishing `ldapSyntaxes` optional and servers do reference syntaxes they never declare.

```php
use FreeDSx\Ldap\Schema\SchemaLoadMode;

$loaded = (new SubschemaLoader(SchemaLoadMode::Lenient))
    ->fromEntry($entry);
```

Unresolved matching rule references are never checked in either mode.

### Confidential Attributes

An attribute carrying the `X-CONFIDENTIAL` extension is withheld from results and search filters unless the identity
holds a grant for it:

```
attributeTypes: ( 1.3.6.1.4.1.99999.1.2 NAME 'secretCode' EQUALITY 2.5.13.5
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-CONFIDENTIAL 'TRUE' )
```

See [Confidential Attributes](Access-Control.md#confidential-attributes) for granting access. Note that replacing the
standard `userPassword` definition without this extension drops its protection.

Extensions are carried forward on merge. A definition replacing one that carries `X-CONFIDENTIAL` keeps that extension
unless it sets a different value for it, so merging schema read from elsewhere cannot silently drop the protection.

## Operational Attributes

The storage backend automatically populates and maintains server-managed operational attributes on every write.
Clients cannot modify these. They are flagged `NO-USER-MODIFICATION` in the schema and client attempts are rejected
with `constraintViolation`.

**Set on `add`:**

| Attribute | Value |
|---|---|
| `createTimestamp` | Current UTC time (`YYYYMMDDHHmmssZ`). |
| `modifyTimestamp` | Same as `createTimestamp` at add time. |
| `creatorsName` | DN of the bound user, or an empty string for anonymous. |
| `modifiersName` | Same as `creatorsName` at add time. |
| `entryUUID` | Random UUID v4 (RFC 4122). |
| `structuralObjectClass` | Most-specific structural objectClass. Only set when schema validation is enabled. |

**Updated on `modify` and `move`:** `modifyTimestamp` and `modifiersName` are refreshed. All other operational
attributes remain unchanged.

**`hasSubordinates` (dynamic):** Never stored. Injected into search results when requested via the `+` shorthand
or by name. Value is `TRUE` if the entry has at least one direct child, `FALSE` otherwise.

## String Matching and Internationalization (RFC 4518)

String matching rules (`caseIgnoreMatch`, `caseExactMatch`, `caseIgnoreIA5Match`, and their substring/ordering
variants) apply a pragmatic profile of [RFC 4518](https://www.rfc-editor.org/rfc/rfc4518) string preparation before
comparing values:

- **Insignificant whitespace is ignored.** Leading/trailing spaces are trimmed and internal runs collapse to a single
  space, so `cn=John  Smith` matches `cn=John Smith`.
- **Ignorable code points are removed** — soft hyphen, zero-width spaces/joiners, BOM, and variation selectors.
- **Unicode space variants are folded** to a normal space (NBSP, ideographic space, en/em spaces, etc.).

### Optional Unicode normalization

Two further steps run only when the supporting capability is available:

| Step | Provided by | Without it |
|---|---|---|
| NFKC normalization (compatibility forms, composed/decomposed equivalence) | `ext-intl` **or** `symfony/polyfill-intl-normalizer` | Skipped |
| Unicode-aware case folding (e.g. `É` ↔ `é`) | `ext-mbstring` **or** `symfony/polyfill-mbstring` | ASCII-only case folding |

ASCII matching is always identical regardless of the above. For byte-identical matching of **non-ASCII** values across
hosts with differing extensions, install the polyfills (or the extensions) so every host normalizes the same way:

```bash
composer require symfony/polyfill-intl-normalizer symfony/polyfill-mbstring
```

### Notes

- `caseExactMatch` preserves case but still ignores insignificant whitespace and applies NFKC — it is no longer a raw
  byte comparison. `octetStringMatch` (used by binary attributes such as `userPassword`) remains byte-exact.
- Distinguished name matching is not affected by this profile.
- The Prohibit and Bidirectional steps of RFC 4518 are not implemented.
