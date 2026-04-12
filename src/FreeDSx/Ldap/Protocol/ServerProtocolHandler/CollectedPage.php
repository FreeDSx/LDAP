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

/**
 * Holds the result of a single generator collection pass in a paging operation.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class CollectedPage
{
    /**
     * @param Entry[] $entries
     */
    public function __construct(
        public readonly array $entries,
        public readonly bool $isGeneratorExhausted,
        public readonly bool $isSizeLimitExceeded,
    ) {
    }
}
