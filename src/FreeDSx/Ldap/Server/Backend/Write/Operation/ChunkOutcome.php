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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation;

/**
 * What one transaction of a subtree delete removed, and what it left for a later one.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ChunkOutcome
{
    /**
     * @param list<string> $strays children found outside the transaction's entries, as canonical DNs
     * @param list<string> $blocked entries kept because a stray sits beneath them, as canonical DNs
     */
    public function __construct(
        public int $removed,
        public bool $baseRemoved,
        public array $strays = [],
        public array $blocked = [],
    ) {}
}
