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

namespace FreeDSx\Ldap\Server\Metrics\Observation;

/**
 * A connection lifecycle event reported to a metrics recorder.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ConnectionObservation: string
{
    case Opened = 'opened';

    case Closed = 'closed';

    case Rejected = 'rejected';

    case WriteTimeout = 'write_timeout';

    case IdleTimeout = 'idle_timeout';

    case RequestSizeExceeded = 'request_size_exceeded';

    case ProtocolError = 'protocol_error';

    case Unavailable = 'unavailable';
}
