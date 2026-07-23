# Database Schema (PDO Storage)

The SQLite and MySQL storage backends keep their tables under a fixed schema. The schema ships with the library as SQL
files, so you can apply and version it with your own database tooling. This page covers how the schema is created and
how to manage it yourself.

* [Automatic Setup](#automatic-setup)
* [The Schema Files](#the-schema-files)
* [Managing the Schema Yourself](#managing-the-schema-yourself)
* [Versioning](#versioning)
* [The Change Journal Tables](#the-change-journal-tables)

## Automatic Setup

By default the SQLite and MySQL adapters create their tables the first time they connect, using
`CREATE TABLE IF NOT EXISTS`, so a fresh database just works. Re-connecting is a no-op. This is convenient for testing
and development use.

This applies the baseline schema only. The library never runs migration deltas, so automatic setup does not upgrade an
existing database to a newer schema; it only brings a fresh one up to the current baseline.

## The Schema Files

The schema ships in the package under `resources/schema`:

* `resources/schema/<dialect>/baseline.sql` is the current full schema. Applying it to a fresh database produces a
  working directory, and applying it again is a no-op.
* `resources/schema/<dialect>/migrations/` holds versioned delta files, named `V<n>__<description>.sql`, added when the
  schema changes.

Point your migration tool at these files, or copy them into your project. If you would rather get the baseline as a
string in code, `PdoStorage::schemaDdl(new SqliteDialect())` and `PdoStorage::schemaDdl(new MysqlDialect())` return the same content.

## Managing the Schema Yourself

For a managed database you usually want to apply schema changes with your own tooling rather than have the library issue
DDL on startup. Turn automatic setup off with the `initializeSchema` flag on the `PdoConfig`, then pass the config to
`setStorageConfig()` or the `ServerOptions` constructor:

```php
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;

$storageConfig = PdoConfig::forSqlite('/var/lib/freedsx/directory.sqlite')
    ->setInitializeSchema(false);
```

With it off, the adapter never runs any DDL on connect. Creating and updating the tables is entirely up to you, using
the schema files above. The library does not migrate your database; it ships the schema, and you decide when and how to
apply it.

## Versioning

`PdoStorage::SCHEMA_VERSION` is the current schema revision. Each release notes any schema change in the CHANGELOG, so
you can tell whether an upgrade needs a migration and which delta to apply. A fresh database applies the baseline; an
existing database applies the delta files newer than its current version, with your own migration tool.

## The Change Journal Tables

When [directory synchronization](Replication.md) is enabled, the schema also includes the change journal tables
(`ldap_change_journal` and `ldap_change_journal_seq`). They are versioned and migrated the same way as the rest of the
schema.

The journal has two roles: a replication window that consumers read, and, when configured, a durable audit record of
changes. A replication consumer can always recover by doing a full refresh, but the audit record cannot be recovered
once it is discarded, so migrate the journal tables like any other table.
