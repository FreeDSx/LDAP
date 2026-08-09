<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\Logging;

/**
 * Canonical PSR-3 context keys for {@see EventLogger::record()} call sites.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class EventContext
{
    public const EVENT = 'event';

    public const MESSAGE_ID = 'message_id';

    // Connection scope
    public const PID = 'pid';

    public const CONN_ID = 'conn_id';

    public const REMOTE_IP = 'remote_ip';

    // Nested sub-array keys
    public const SUBJECT = 'subject';

    public const TARGET = 'target';

    public const AUTHORIZED_BY = 'authorized_by';

    // Used within `subject` (who acted) or `target` (what was acted on)
    public const USERNAME = 'username';

    public const DN = 'dn';

    // Per-event
    public const OPERATION = 'operation';

    public const RESULT_CODE = 'result_code';

    public const REASON = 'reason';

    public const VALIDATION_MODE = 'validation_mode';

    public const REASON_CODE = 'reason_code';

    public const REASON_MESSAGE = 'reason_message';

    public const MECHANISM = 'mechanism';

    public const VERSION = 'version';

    public const ATTRIBUTE = 'attribute';

    public const MATCH = 'match';

    public const CONTROL_OIDS = 'control_oids';

    public const AUTHZ_ID = 'authz_id';

    public const BASE_DN = 'base_dn';

    public const SCOPE = 'scope';

    public const ENTRIES_RETURNED = 'entries_returned';

    public const REMOVED = 'removed';

    public const LIMIT = 'limit';

    public const DURATION_SECONDS = 'duration_seconds';

    public const NEW_RDN = 'new_rdn';

    public const NEW_SUPERIOR_DN = 'new_superior_dn';

    // Set when an event was triggered by a Throwable
    public const EXCEPTION_CLASS = 'exception_class';

    public const EXCEPTION_MESSAGE = 'exception_message';

    public const EXCEPTION_ORIGIN = 'exception_origin';

    public const EXCEPTION_TRACE = 'exception_trace';
}
