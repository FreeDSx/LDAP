Schema Validation
=================

* [Default Behavior](#default-behavior)
* [What Gets Validated](#what-gets-validated)
* [Entry Requirements](#entry-requirements)
    * [extensibleObject](#extensibleobject)
* [Validation Mode](#validation-mode)
    * [ServerOptions:setSchemaValidationMode](#setschemavalidationmode)
* [Custom Schema](#custom-schema)
    * [ServerOptions:setSchema](#setschema)
    * [Loading Schema](#loading-schema)
        * [What Is Not Read](#what-is-not-read)
        * [SchemaLoadMode](#schemaloadmode)
    * [Confidential Attributes](#confidential-attributes)
    * [Building Definitions in PHP](#building-definitions-in-php)
* [Operational Attributes](#operational-attributes)
* [String Matching and Internationalization (RFC 4518)](#string-matching-and-internationalization-rfc-4518)

Configuring backend storage automatically enables schema validation using the built-in RFC 4519 schema in
`Strict` mode.

## Default Behavior

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(new ServerOptions());
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

Adding `extensibleObject` as an auxiliary class bypasses the attribute-set checks.

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

## Validation Mode

------------------
#### setSchemaValidationMode

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
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(
    (new ServerOptions())
        ->setSchemaValidationMode(SchemaValidationMode::Lenient)
);
```

Beyond the server-wide mode, an authorized client can relax validation for a *single* Add/Modify with the Relax Rules
control (logged with `validation_mode: relaxed`). It is ACL-gated — see [Control Rules](Access-Control.md#control-rules).

## Custom Schema

------------------
#### setSchema

Replaces the active schema. Use `StandardSchemaProvider::buildCore()->merge(...)` to extend the
standard definitions rather than replace them.

**Default**: `StandardSchemaProvider::buildCore()`

Schema is written in RFC 4512 description strings, which is the form every directory publishes and the form
`.schema` and `.ldif` schema files use. Load those directly rather than transcribing them. Building definitions in
PHP is for adding a handful of your own.

### Loading Schema

`SubschemaLoader` reads definitions from a subschema entry in LDIF. The file can be one you maintain yourself:

```php
use FreeDSx\Ldap\Schema\StandardSchemaProvider;
use FreeDSx\Ldap\Schema\SubschemaLoader;
use FreeDSx\Ldap\ServerOptions;

$loaded = (new SubschemaLoader())->fromLdifFile('/path/to/schema.ldif');

$options = (new ServerOptions())->setSchema(
    StandardSchemaProvider::buildCore()->merge($loaded),
);
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

To adopt the schema of an existing directory instead, read its subschema entry and pass that:

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
Filters against such an attribute fall back to byte-exact comparison rather than failing.

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

### Building Definitions in PHP

Definitions are also constructible directly, which suits schema generated at runtime. `AttributeType`, `ObjectClass`
and `LdapSyntax` map one to one onto the description string fields:

```php
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\StandardSchemaProvider;
use FreeDSx\Ldap\ServerOptions;

$schema = StandardSchemaProvider::buildCore()->merge(
    (new Schema())->addAttributeType(new AttributeType(
        oid: '1.3.6.1.4.1.99999.1.1',
        names: ['myCustomAttr'],
        equalityOid: '2.5.13.2',
        syntaxOid: '1.3.6.1.4.1.1466.115.121.1.15',
    )),
);

$options = (new ServerOptions())->setSchema($schema);
```

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
