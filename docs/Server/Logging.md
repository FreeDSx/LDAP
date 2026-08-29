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

The server emits structured audit events through a configured PSR-3 logger. Each event has a stable string discriminator
(e.g. `bind.success`, `entry.modified`, `authz.denied.write`) and a context array with predictable keys.

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

| Event                       | Default | Level  | Fires when                                                |
|-----------------------------|---------|--------|-----------------------------------------------------------|
| `bind.success`              | on      | info   | Simple or SASL bind authenticates a user                  |
| `bind.failure`              | on      | notice | Bind authentication fails                                 |
| `bind.anonymous`            | on      | info   | An anonymous bind is performed                            |
| `starttls.succeeded`        | on      | info   | TLS is negotiated on the connection                       |
| `starttls.failed`           | on      | notice | StartTLS rejected (no cert / already encrypted)           |
| `password_modify.success`   | on      | info   | Password modify completes                                 |
| `password_modify.failed`    | on      | notice | Password modify rejected by ACL or constraint             |
| `authz.denied.write`        | on      | notice | ACL denies an Add / Modify / Delete / ModifyDn / Compare  |
| `authz.denied.read`         | on      | notice | ACL denies a Search or Paging request                     |
| `control.critical.rejected` | on      | notice | Client sent a critical control the server doesn't support |
| `schema.violation`          | on      | notice | Add/Modify violates the schema (rejected, or allowed under Lenient mode / the Relax control) |
| `session.disconnect_notice` | on      | notice | Server sends an unsolicited Notice of Disconnect          |
| `paging.session_evicted`    | on      | notice | A connection hit `setMaxPagingSessions`, so its least recently started paged search was discarded |
| `entry.replaced`            | on      | info   | While seeding, an entry already at that DN was overwritten |
| `import.completed`          | on      | info   | Seeding committed, carrying the entries added and replaced |
| `import.failed`             | on      | warning | Seeding was rolled back, carrying how far it got          |
| `entry.added`               | off     | info   | Add succeeds (audit-trail)                                |
| `entry.modified`            | off     | info   | Modify succeeds (audit-trail)                             |
| `entry.deleted`             | off     | info   | Delete succeeds (audit-trail)                             |
| `entry.renamed`             | off     | info   | ModifyDn succeeds (audit-trail)                           |
| `search.authorized`         | off     | info   | Search/Paging completes after authorization (audit-trail) |
| `compare.completed`         | off     | info   | Compare completes (audit-trail)                           |

The audit-trail events are opt-in because they fire on every successful write or read; enable them when full auditing is
needed, otherwise the default set covers security-relevant events without an overwhelming amount of noise.

## Event Context Shape

Every event carries a structured `context` array with a stable shape:

| Key                                                        | Source                                                             | Notes                                                                                              |
|------------------------------------------------------------|--------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| `event`                                                    | always                                                             | The event discriminator string (same as the log message).                                          |
| `message_id`                                               | per-request events                                                 | LDAP message ID — correlates server log lines with the client's view.                              |
| `control_oids`                                             | per-request events                                                 | List of all control OIDs attached to the request (empty list when none).                           |
| `subject`                                                  | events with a bound identity                                       | Sub-array with `username` and (if authenticated) `dn`. Omitted for events with no acting identity. |
| `target`                                                   | events that act on an entry                                        | Sub-array; shape varies (see below).                                                               |
| `operation`                                                | write / compare events                                             | One of `add`, `modify`, `delete`, `modify_dn`, `compare`.                                          |
| `result_code`                                              | failure events                                                     | LDAP result code from the caught `OperationException`.                                             |
| `reason`                                                   | failure events                                                     | Human-readable diagnostic from the exception.                                                      |
| `validation_mode`                                          | `schema.violation`                                                 | How it was handled: `strict` (rejected), `lenient` (allowed by policy), or `relaxed` (Relax control). |
| `mechanism`, `version`                                     | bind events                                                        | SASL mechanism name (or `simple`) and LDAP protocol version.                                       |
| `entries_added`, `entries_replaced`                        | `import.completed`, `import.failed`                                | Counts for the batch. On a failure they say how far it got before the rollback.                    |
| `match`, `attribute`                                       | compare events                                                     | Match outcome + attribute compared.                                                                |
| `entries_returned`                                         | search events                                                      | Count of entries delivered to the client.                                                          |
| `base_dn`, `scope`                                         | search events                                                      | Inside `target`.                                                                                   |
| `new_rdn`, `new_superior_dn`                               | `entry.renamed`                                                    | Inside `target`.                                                                                   |
| `pid`, `conn_id`, `remote_ip`                              | connection scope                                                   | Auto-merged into every event from the runner's `ConnectionContext`.                                |
| `reason_code`, `reason_message`                            | `session.disconnect_notice`                                        | The Notice of Disconnect's wire-level reason.                                                      |
| `exception_class`, `exception_message`, `exception_origin` | `session.disconnect_notice` triggered by an unexpected `Throwable` | FQCN, message, `file:line` of the throw site.                                                      |
| `exception_trace`                                          | as above, only when policy opts in                                 | Full `getTraceAsString()`. Disabled by default; see [Exception Traces](#exception-traces).         |

`subject.dn` is the acting identity. `target.dn` is the entry being acted on.

Example: a successful paged search produces a record like (audit-trail event opt-in):

```json
{
  "event": "search.authorized",
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

* `entry.added`
* `entry.modified`
* `entry.deleted`
* `entry.renamed`
* `search.authorized`
* `compare.completed`

### Exception Traces

By default, `session.disconnect_notice` events triggered by an unexpected `Throwable` carry only:

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
