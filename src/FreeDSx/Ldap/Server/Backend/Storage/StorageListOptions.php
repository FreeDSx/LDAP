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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;

/**
 * A DTO encapsulating all parameters for a storage list operation, decoupled
 * from LDAP protocol objects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class StorageListOptions
{
    public function __construct(
        public readonly Dn $baseDn,
        public readonly bool $subtree,
        public readonly FilterInterface $filter,
        public readonly int $timeLimit = 0,
        public readonly int $sizeLimit = 0,
    ) {
    }

    /**
     * Create options that match all entries within the given scope.
     *
     * Convenient for internal operations (e.g. hasChildren) and tests that do not need a meaningful filter.
     */
    public static function matchAll(
        Dn $baseDn,
        bool $subtree,
        int $timeLimit = 0,
    ): self {
        return new self(
            baseDn: $baseDn,
            subtree: $subtree,
            filter: new AndFilter(),
            timeLimit: $timeLimit,
        );
    }
}
