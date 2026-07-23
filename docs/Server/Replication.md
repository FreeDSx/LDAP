# Directory Synchronization (Provider)

The server can act as an RFC 4533 content-synchronization provider. It records every write in an append-only change
journal and serves those changes to sync consumers, so a client (or a downstream replica) can track the directory and
stay in step with it.

This page covers standing up and operating the provider side. For consuming sync as a client, see
[SyncRepl](../Client/SyncRepl.md).

Sync is off by default.

* [Quick Start](#quick-start)
* [How It Works](#how-it-works)
* [Storage and Runner Requirements](#storage-and-runner-requirements)
* [Access Control](#access-control)
* [Poll vs Listen](#poll-vs-listen)
* [Retention](#retention)
* [Origin and Cookies](#origin-and-cookies)
* [Operational Notes](#operational-notes)
* [Read-Only Replica](#read-only-replica)

## Quick Start

Sync needs three things: turn it on, use a storage that supports it, and grant the sync control in access control. The
sync control is privileged, so it is the one access-control addition sync requires. Your normal operation and attribute
rules are unchanged, and they still have to permit the search over the base being synced.

```php
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\ServerOptions;

// The one sync-specific grant: the privileged sync control, over the base to sync.
$syncGrant = ControlRule::allow(
    Subject::authenticated(),
    Target::subtree('dc=example,dc=com'),
    Control::OID_SYNC_REQUEST,
);

// Add that grant to your directory's AclRules (see the Access Control page for the rest).
$aclRules = $myAclRules->withControlRules($syncGrant);

// A storage config that is visible across connections (see Storage and Runner Requirements below).
$storageConfig = PdoConfig::forSqlite('/var/lib/freedsx/directory.sqlite');

$options = (new ServerOptions($storageConfig))
    ->setSyncEnabled(true)
    ->setAclRules($aclRules);

$server = new LdapServer($options);
```

A consumer can now run a sync against the server.

## How It Works

With sync enabled, every write (add, modify, delete, and rename) appends one record to the change journal in the same
transaction as the write, so a change and its journal record are committed together. Each record carries an increasing
sequence number, the configured origin, a timestamp, the entry's UUID and DN, and, for deletes, a copy of the removed
entry.

A consumer presents a cookie, which is a marker of how far it has already read. The server then sends the changes that
came after that point. The journal is the single source behind sync and change auditing.

## Storage and Runner Requirements

Every built-in storage option records changes for sync. A custom storage adapter has to support change journaling to
take part. The constraint that matters is cross-connection visibility. A consumer needs to see writes made on other
connections, which means the recorded changes must be visible to whichever process is serving those connections.

| Runner | Concurrency model | What to use |
| --- | --- | --- |
| PCNTL (default) | One forked child process per connection | A storage that is shared across processes, such as SQLite, MySQL, or JSON file. In-memory storage is private to each child and will not serve writes made on other connections. |
| Swoole | One process, one coroutine per connection | Any storage, including in-memory, since everything shares one process. |

In short, the persistent listen mode is available when either the Swoole runner is in use or the storage is shared
across processes. Otherwise the server still answers a one-time poll but declines the persistent listen.

## Access Control

The content-sync control (OID `1.3.6.1.4.1.4203.1.9.1.1`) is treated as a privileged control by default, so it is
denied unless access control explicitly grants it. Simple allow/deny access control denies all privileged controls, so
you need rule-based access control. Add one control rule that grants the sync control, as shown in the
[Quick Start](#quick-start); everything else about your policy, including which identities may search the base being
synced, is your normal configuration. See [Access Control](Access-Control.md).

If you need to change which controls require an explicit grant, use `ServerOptions::setPrivilegedControls(...)`.

A sync consumer receives full entries, including attributes that are hidden from ordinary searches such as
`userPassword`, because a replica has to be a faithful copy. The sync control is the privileged gate that decides this,
so grant it only to identities you trust with the whole directory. Attribute read rules like the secure default's
`userPassword` restriction still apply to normal searches by that identity; they do not trim what replication sends.

## Poll vs Listen

The consumer chooses how it reads; the provider supports both:

* Poll: the consumer receives the current content, or the changes since its saved cookie, and the request then ends.
  This works on both runners with any journaling storage.
* Listen: the request stays open and the server sends changes as they happen. This needs the runner-or-storage
  condition described above. While a listen is idle, the server sends a periodic keepalive that advances the consumer's
  cookie and lets the server notice a consumer that has gone away.

## Retention

The journal grows with every write, so bound it with a retention policy on the journal configuration:

```php
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;

$retention = new RetentionPolicy(
    maxRecords: 1_000_000,               // ceiling on retained records (null for no count limit)
    maxAgeSeconds: ((60 * 60) * 24) * 7, // age horizon, here seven days (null for no age limit)
);

$journalConfig = new ChangeJournalConfig(
    origin: new ReplicaId('dc1'),
    retention: $retention,
);

$options->setChangeJournalConfig($journalConfig);
```

Set either limit, both, or neither. The default policy keeps everything. A record becomes eligible for removal once it
fails either limit.

When a policy sets at least one limit, a retention sweep runs about every sixty seconds on both runners, and prunes off
to the side so it does not block new connections. It runs as a short-lived forked child under PCNTL, or a background
coroutine under Swoole. A prune that removes records writes a `journal.pruned` entry to the event log with the count and
duration. See [Logging](Logging.md).

There is a sizing trade-off. Pruning moves the oldest point the journal can still serve. A consumer whose saved cookie
is older than that point cannot be brought up to date incrementally, so it receives a full refresh on its next sync.
Choose retention limits that cover the longest window a consumer might be offline.

On a PDO backend the journal lives in tables that are part of the storage schema. See
[Database Schema](Database-Schema.md) for creating and managing it.

## Origin and Cookies

Each journal has an origin, which defaults to `local`. Set a stable, unique origin for each provider through the
journal configuration. It is stamped into the sync cookie so a consumer can tell which server a saved cookie came from.
Do not reuse one origin across different directories.

The cookie itself is opaque. It stands for an origin and a position in the change history. Consumers save it and resume
with it. Neither side should try to read or build it by hand; treat it as a token handed out by the server.

## Operational Notes

* Enabling sync with a journaling storage is what records changes. The access-control grant is what exposes the feed to
  clients. A working provider needs both.
* The journal record is written inside the same transaction as the change, so there is no separate flush to coordinate
  and no window where a change is stored without its record.
* Consuming the feed: a client uses the [SyncRepl](../Client/SyncRepl.md) helper to poll or listen.
* Sync has no dedicated `cn=monitor` counters yet. Journal prunes appear in the event log rather than in metrics.

## Read-Only Replica

A FreeDSx server can run as a read-only replica of a provider. It serves reads from a local copy of the directory and
runs a background daemon that keeps that copy in step with the provider over RFC 4533. Client writes to a replica are not
accepted; by default they are referred to the provider.

Build the server with `ServerOptions::forReplica(...)`. A `ReplicaConfig` describes how to reach and authenticate to the
provider; the replica's own listener and storage are configured as usual.

```php
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\ReplicaConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\FileReplicationCheckpoint;
use FreeDSx\Ldap\ServerOptions;

// Persist the sync cookie so the replica resumes across restarts (the default is in-memory).
$checkpoint = new FileReplicationCheckpoint('/var/lib/freedsx/replica.cookie');

$replicaConfig = new ReplicaConfig(
    (new ClientOptions())
        ->setServers(['provider.example.com'])
        ->setPort(636)
        ->setUseSsl(true)
        ->setBaseDn('dc=example,dc=com'),
    $checkpoint,
);

// How the replica authenticates to the provider (a simple bind here; use Operations::bindSasl() for SASL/EXTERNAL).
$replicaConfig->setBind(Operations::bind('cn=replica,dc=example,dc=com', 'secret'));

$options = ServerOptions::forReplica(
    $replicaConfig,
    PdoConfig::forSqlite('/var/lib/freedsx/replica.sqlite'),
);

(new LdapServer($options))->run();
```

The base DN on the primary `ClientOptions` is the subtree the replica mirrors; it must fall within the sync grant the
provider gives the replica's bind identity.

### How It Works

The replica serves client reads and runs the sync daemon as a managed background task. The daemon connects to the
provider, performs an initial refresh, then listens for changes and applies them verbatim to the replica's storage,
preserving the provider's UUIDs and timestamps. It checkpoints its cookie so it resumes where it left off, reconciles
deletions on a full refresh, and reconnects with bounded backoff if the connection drops. Changes are applied as a leaf;
the replica does not re-journal them.

### Writes Are Refused

Any client write to a replica (add, modify, delete, rename, password modify) is refused. By default it is returned as a
referral to the provider; call `ReplicaConfig::setReferWrites(false)` to reject it with `unwillingToPerform` instead.
Reads, binds, compares, and StartTLS are served normally.

### Storage Requirement

Under the PCNTL runner the sync daemon and the connection workers are separate processes, so the replica's storage must
be shared across processes (SQLite, MySQL, or JSON file); a forking replica on in-memory storage fails at startup. Under
Swoole (one process) any storage works.

### Security: Two Gates, and ACLs Do Not Replicate

Access control is enforced independently on each side, and FreeDSx ACL is server configuration that does not replicate:

* On the provider, the read access granted to the replica's bind identity bounds what data reaches the replica.
* On the replica, its own access control bounds what clients reading from it may see. A replica with a more permissive
  policy than the provider can expose data the provider would not.

Because the two are separate, configure and review both. A replica does not inherit the provider's policy.

### Password Policy

With a password policy enabled, a replica applies the provider's lockout, expiry, and grace state, and bind failures
against the replica count toward the account's lockout across the whole cluster. A brute-force attempt spread over
several replicas is caught the same as one against a single server.

To turn this on:

- Enable a password policy on both the provider and the replica with `setPasswordPolicy(...)`.
- On the provider, grant the replica's bind identity with `withReplicaGrants(...)`. It sets up everything a replica
  identity needs, so use it in place of the sync-only grant from the Quick Start.
- Give the replica PDO storage (SQLite or MySQL). JSON-file storage is not yet supported for replica password-policy
  state or forwarding.

```php
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;

$aclRules = $myAclRules->withReplicaGrants(
    Subject::dn('cn=replica,dc=example,dc=com'),
    Target::subtree('dc=example,dc=com'),
);
```

Cluster-wide lockout is not instantaneous, so keep replicas behind connection rate limiting. If the provider is not a
FreeDSx server, the replica still enforces the lockout state it receives but does not contribute its own.
