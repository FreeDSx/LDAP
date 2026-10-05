Server Logging
================

* [Overview](#overview)
* [Wiring a Logger](#wiring-a-logger)
* [Event Catalog](#event-catalog)
* [Event Context Shape](#event-context-shape)
* [Tuning the Event Policy](#tuning-the-event-policy)
    * [Audit-Trail Events](#audit-trail-events)
    * [Exception Traces](#exception-traces)
    * [Custom Policies](#custom-policies)

## Overview

The server emits structured events through a configured PSR-3 logger. Each event has a stable name (e.g.
`ldap.bind.success`, `ldap.entry.modified`, `storage.journal.pruned`), carried in the context under `event`, a readable
log message describing what happened, and a context array with predictable keys.

Names are grouped by what they are about:

* `ldap.*`: LDAP protocol semantics, such as binds, writes, access control and the password policy.
* `storage.*`: storage maintenance, such as seeding and journal retention.
* `server.*`: the server process and its client connections.

Without a configured logger, the server runs silently.

## Wiring a Logger

Any PSR-3 `LoggerInterface` works — set it on `ServerOptions`:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;
use Psr\Log\LoggerInterface;

$server = new LdapServer((new ServerOptions($storageConfig))->setLogger($logger));
```

## Event Catalog

Each event's log message is defined next to its case in `ServerEvent`; the tables say when it fires.

### LDAP Events

| Event                                 | Default | Level   | Fires when                                                |
|---------------------------------------|---------|---------|-----------------------------------------------------------|
| `ldap.bind.success`                   | on      | info    | Simple or SASL bind authenticates a user                  |
| `ldap.bind.failure`                   | on      | notice  | Bind authentication fails                                 |
| `ldap.bind.anonymous`                 | on      | info    | An anonymous bind is performed                            |
| `ldap.starttls.succeeded`             | on      | info    | TLS is negotiated on the connection                       |
| `ldap.starttls.failed`                | on      | notice  | StartTLS rejected (no cert / already encrypted)           |
| `ldap.starttls.buffer_discarded`      | on      | warning | Plaintext was pipelined behind a StartTLS request and dropped unread |
| `ldap.password_modify.success`        | on      | info    | Password modify completes                                 |
| `ldap.password_modify.failed`         | on      | notice  | Password modify rejected by ACL or constraint             |
| `ldap.authz.denied.write`             | on      | notice  | ACL denies an Add / Modify / Delete / ModifyDn / Compare  |
| `ldap.authz.denied.read`              | on      | notice  | ACL denies a Search or Paging request                     |
| `ldap.authz.denied.proxy`             | on      | notice  | A Proxied Authorization control is refused                |
| `ldap.control.critical.rejected`      | on      | notice  | Client sent a critical control the server doesn't support |
| `ldap.schema.violation`               | on      | notice  | Add/Modify violates the schema (rejected, or allowed under Lenient mode / the Relax control) |
| `ldap.session.disconnect_notice`      | on      | notice  | Server sends an unsolicited Notice of Disconnect          |
| `ldap.paging.session_evicted`         | on      | notice  | A connection hit `setMaxPagingSessions`, so its least recently started paged search was discarded |
| `ldap.sync.entry_skipped`             | on      | warning | An entry with an unusable entryUUID was left out of a content synchronization |
| `ldap.password_policy.account_locked` | on      | warning | Failed binds locked an account                            |
| `ldap.password_policy.account_unlocked` | on    | info    | A locked account bound again once its lockout lapsed      |
| `ldap.password_policy.expired`        | on      | notice  | A bind was refused because the password expired           |
| `ldap.password_policy.must_change`    | on      | info    | A bind succeeded with a reset password that must be changed first |
| `ldap.password_policy.grace_login`    | on      | info    | A bind used one of an expired password's grace logins     |
| `ldap.password_policy.change_rejected` | on     | notice  | A password change violated the password policy            |
| `ldap.operation.refused`              | off     | notice  | A bind or authorization failure refused a request before it was processed |
| `ldap.message.decode_failed`          | off     | notice  | A request could not be decoded and was answered with an error |
| `ldap.entry.added`                    | off     | info    | Add succeeds (audit-trail)                                |
| `ldap.entry.modified`                 | off     | info    | Modify succeeds (audit-trail)                             |
| `ldap.entry.deleted`                  | off     | info    | Delete succeeds (audit-trail)                             |
| `ldap.entry.renamed`                  | off     | info    | ModifyDn succeeds (audit-trail)                           |
| `ldap.search.authorized`              | off     | info    | Search/Paging completes after authorization (audit-trail) |
| `ldap.compare.completed`              | off     | info    | Compare completes (audit-trail)                           |

### Storage Events

| Event                          | Default | Level   | Fires when                                                |
|--------------------------------|---------|---------|-----------------------------------------------------------|
| `storage.import.entry_skipped` | on      | info    | While seeding with `setSkipExisting()`, an entry already at that DN was left untouched |
| `storage.import.completed`     | on      | info    | Seeding committed, carrying the entries added and skipped |
| `storage.import.failed`        | on      | warning | Seeding was rolled back, carrying how far it got          |
| `storage.journal.pruned`       | on      | info    | Journal retention removed records                         |
| `storage.journal.prune_failed` | on      | warning | Journal retention failed                                  |

### Server Events

| Event                         | Default | Level  | Fires when                                                |
|-------------------------------|---------|--------|-----------------------------------------------------------|
| `server.client.write_timeout` | on      | notice | A client stopped reading and its connection was closed    |
| `server.client.idle_timeout`  | on      | notice | A client was idle past the read timeout and its connection was closed |

The audit-trail events are opt-in because they fire on every successful write or read; enable them when full auditing is
needed, otherwise the default set covers security-relevant events without an overwhelming amount of noise.

## Event Context Shape

Every event carries a structured `context` array with a stable shape:

| Key                                                        | Source                                                             | Notes                                                                                              |
|------------------------------------------------------------|--------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| `event`                                                    | always                                                             | The event's name, for filtering. The log message is a readable sentence describing it.             |
| `message_id`                                               | per-request events                                                 | LDAP message ID — correlates server log lines with the client's view.                              |
| `control_oids`                                             | per-request events                                                 | List of all control OIDs attached to the request (empty list when none).                           |
| `subject`                                                  | events with a bound identity                                       | Sub-array with `username` and (if authenticated) `dn`. Omitted for events with no acting identity. |
| `target`                                                   | events that act on an entry                                        | Sub-array; shape varies (see below).                                                               |
| `operation`                                                | write / compare events                                             | One of `add`, `modify`, `delete`, `modify_dn`, `compare`.                                          |
| `result_code`                                              | failure events                                                     | LDAP result code from the caught `OperationException`.                                             |
| `reason`                                                   | failure events, `ldap.starttls.buffer_discarded`                   | Human-readable diagnostic. Taken from the exception on failure events.                             |
| `validation_mode`                                          | `ldap.schema.violation`                                            | How it was handled: `strict` (rejected), `lenient` (allowed by policy), or `relaxed` (Relax control). |
| `mechanism`, `version`                                     | bind events                                                        | SASL mechanism name (or `simple`) and LDAP protocol version.                                       |
| `entries_added`, `entries_skipped`                         | `storage.import.completed`, `storage.import.failed`                | Counts for the batch. On a failure they say how far it got before the rollback.                    |
| `match`, `attribute`                                       | compare events                                                     | Match outcome + attribute compared.                                                                |
| `entries_returned`                                         | search events                                                      | Count of entries delivered to the client.                                                          |
| `base_dn`, `scope`                                         | search events                                                      | Inside `target`.                                                                                   |
| `new_rdn`, `new_superior_dn`                               | `ldap.entry.renamed`                                               | Inside `target`.                                                                                   |
| `pid`, `conn_id`, `remote_ip`                              | connection scope                                                   | Auto-merged into every event from the runner's `ConnectionContext`.                                |
| `reason_code`, `reason_message`                            | `ldap.session.disconnect_notice`                                   | The Notice of Disconnect's wire-level reason.                                                      |
| `exception_class`, `exception_message`, `exception_origin` | events caused by an exception, e.g. `ldap.session.disconnect_notice` triggered by an unexpected `Throwable` | FQCN, message, `file:line` of the throw site.                                                      |
| `exception_trace`                                          | as above, only when policy opts in                                 | Full `getTraceAsString()`. Disabled by default; see [Exception Traces](#exception-traces).         |

`subject.dn` is the acting identity. `target.dn` is the entry being acted on.

Example: a successful paged search produces a record like (audit-trail event opt-in):

```json
{
  "event": "ldap.search.authorized",
  "message_id": 1,
  "pid": 5642,
  "entries_returned": 50,
  "subject": { "username": "cn=alice,dc=example,dc=com", "dn": "cn=alice,dc=example,dc=com" },
  "target":  { "base_dn": "ou=people,dc=example,dc=com", "scope": 2 },
  "control_oids": ["1.2.840.113556.1.4.319"]
}
```

## Tuning the Event Policy

`EventLogPolicy` is an immutable value object passed via `ServerOptions::setEventLogPolicy()`. The default policy is
what the table above documents.

### Audit-Trail Events

Enable the per-operation success events as a group:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;

$options = (new ServerOptions($storageConfig))
    ->setEventLogPolicy(EventLogPolicy::default()->withAuditTrail());
```

`withAuditTrail()` enables the following on top of the default set:

* `ldap.entry.added`
* `ldap.entry.modified`
* `ldap.entry.deleted`
* `ldap.entry.renamed`
* `ldap.search.authorized`
* `ldap.compare.completed`

### Exception Traces

By default, events caused by an exception (such as `ldap.session.disconnect_notice` triggered by an unexpected
`Throwable`) carry only:

* `exception_class`
* `exception_message`
* `exception_origin`

Enough to identify what threw and where. To include the full stack trace:

```php
$options = (new ServerOptions($storageConfig))
    ->setEventLogPolicy(EventLogPolicy::default()->withExceptionTraces());
```

The trace is added under `exception_trace` only when this flag is set.

### Custom Policies

Compose policies fluently:

```php
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;

$policy = EventLogPolicy::default()
    ->withAuditTrail()
    ->withExceptionTraces()
    ->disable(ServerEvent::CompareCompleted)
    ->enable(ServerEvent::EntryDeleted);
```

Other factories:

- `EventLogPolicy::none()` : every event disabled.
- `EventLogPolicy::all()`  : every event enabled.
