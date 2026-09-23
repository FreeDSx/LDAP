# Database Schema (PDO Storage)

The SQLite and MySQL storage backends keep their tables under a fixed schema. The schema ships with the library as SQL
files, so you can apply and version it with your own database tooling. This page covers how the schema is created and
how to manage it yourself.

* [Automatic Setup](#automatic-setup)
* [The Schema Files](#the-schema-files)
* [Managing the Schema Yourself](#managing-the-schema-yourself)
* [Versioning](#versioning)
* [Rebuilding the Indexes](#rebuilding-the-indexes)
* [The Linked Attribute Tables](#the-linked-attribute-tables)
* [The Change Journal Tables](#the-change-journal-tables)

## Automatic Setup

By default the SQLite and MySQL adapters create their tables once at startup, using `CREATE TABLE IF NOT EXISTS`, so a
fresh database just works and a restart is a no-op. This is convenient for testing and development use.

Automatic setup never runs migration deltas, so it does not upgrade an existing database to a newer schema; it only
brings a fresh one up to the current baseline.

## The Schema Files

The schema ships in the package under `resources/pdo-schema`:

* `resources/pdo-schema/<dialect>/baseline.sql` is the current full schema. Applying it to a fresh database produces a
  working directory, and applying it again is a no-op.
* `resources/pdo-schema/<dialect>/migrations/` holds versioned delta files, named `V<n>__<description>.sql`, added when the
  schema changes.

Point your migration tool at these files, or copy them into your project. To get the exact schema your server would
create, including any substring index tables, as one script:

```php
file_put_contents('schema.sql', $server->schemaDdl());
```

## Managing the Schema Yourself

For a managed database you usually want to apply schema changes with your own tooling rather than have the library issue
DDL on startup. Turn automatic setup off with the `initializeSchema` flag on the `PdoConfig`, then pass the config to
`setStorageConfig()` or the `ServerOptions` constructor:

```php
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;

$storageConfig = PdoConfig::forSqlite('/var/lib/freedsx/directory.sqlite')
    ->setInitializeSchema(false);
```

With it off, the adapter never runs any DDL. Creating and updating the tables is entirely up to you, using
the schema files above. The library does not migrate your database; it ships the schema, and you decide when and how to
apply it.

## Versioning

A database records the schema revision it was created from in the `ldap_schema_version` table. Each release notes any
schema change in the CHANGELOG, so you can tell whether an upgrade needs a migration and which delta to apply. A fresh database applies the baseline; an
existing database applies the delta files newer than its current version, with your own migration tool.

## Rebuilding the Indexes

The secondary index tables are derived from each entry as it is written, so a change to how values are indexed only
reaches entries stored afterwards. Rebuild them with `reindex()`:

```php
$server->reindex();
```

It re-stores every entry in one transaction, leaving operational attributes untouched and journaling nothing. Run it
after enabling substring indexing, changing which attributes it covers, or changing an attribute's `EQUALITY` or
`SUBSTR` rule. It rewrites every row, so treat it as maintenance rather than a startup step.

## The Linked Attribute Tables

Values of an attribute the schema marks `X-LINKED` live in `entry_attribute_links`, one row per value, referencing the
target entry by its id rather than sitting in the entry's own row. See
[Linked Attributes](Schema.md#linked-attributes) for what that means for a client.

Both ends reference `entries` with `ON DELETE CASCADE`, which is what drops a reference when its target is deleted and
what makes a rename visible without writing the referring entry. On SQLite that depends on `PRAGMA foreign_keys = ON`,
issued on every connection; a custom `sessionStatements` list that drops it leaves references pointing at entries that
no longer exist.

A value naming an entry that is not stored yet is held in `entry_link_pending`, invisible to reads, and promoted once
an entry with that DN arrives. Client writes never leave anything pending, since an unresolvable name is refused
outright. The table is there for bulk loads and replication, where entries can arrive in any order.

`reindex()` re-resolves the references as it re-stores each entry.

## The Change Journal Tables

When [directory synchronization](Replication.md) is enabled, the schema also includes the change journal tables
(`ldap_change_journal` and `ldap_change_journal_seq`). They are versioned and migrated the same way as the rest of the
schema.

The journal has two roles: a replication window that consumers read, and, when configured, a durable audit record of
changes. A replication consumer can always recover by doing a full refresh, but the audit record cannot be recovered
once it is discarded, so migrate the journal tables like any other table.
