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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\PageCursor;

/**
 * One page of a paging operation, and where the result was left.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class CollectedPage
{
    /**
     * @param Entry[] $entries
     * @param bool $isResultExhausted Whether the result ran out, so no further page can exist.
     * @param ?PageCursor $cursor Where to resume, or null when nothing was read.
     */
    public function __construct(
        public array $entries,
        public bool $isResultExhausted,
        public bool $isSizeLimitExceeded,
        public ?PageCursor $cursor = null,
    ) {}
}
