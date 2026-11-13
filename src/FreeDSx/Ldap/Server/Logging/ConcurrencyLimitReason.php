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
 * Why the configuration limits how many clients the server can serve at once.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ConcurrencyLimitReason: string
{
    /**
     * Several workers were configured, but the storage cannot be shared between processes, so one is used.
     */
    case StorageNotShareable = 'storage_not_shareable';

    /**
     * SQLite runs on a Swoole built without its SQLite hook, where a lock wait blocks the whole worker.
     */
    case StorageBlocksWorker = 'storage_blocks_worker';

    /**
     * A worker serving many clients in one process reaches its open-file limit before the connection limit.
     */
    case OpenFileLimit = 'open_file_limit';

    /**
     * A worker serving many clients in one process can need more than its memory limit before the connection limit.
     */
    case MemoryLimit = 'memory_limit';

    /**
     * The largest request allowed, or any request when there is no size limit, can hold more than the held size.
     */
    case HeldRequestSize = 'held_request_size';

    /**
     * The process has no memory limit, leaving the held request size at a fixed size.
     */
    case NoMemoryLimit = 'no_memory_limit';
}
