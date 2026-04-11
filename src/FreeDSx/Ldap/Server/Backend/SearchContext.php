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

namespace FreeDSx\Ldap\Server\Backend;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Search\Filter\FilterInterface;

/**
 * Encapsulates the parameters of an LDAP search operation for use by
 * LdapBackendInterface::search().
 *
 * The backend receives the complete context including the filter. It may
 * translate the filter to a native query language (SQL, MongoDB, etc.) or
 * ignore it and yield all in-scope entries for the framework to filter.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SearchContext
{
    /**
     * @param Attribute[] $attributes Requested attribute list; empty means all attributes.
     */
    public function __construct(
        readonly public Dn $baseDn,
        readonly public int $scope,
        readonly public FilterInterface $filter,
        readonly public array $attributes,
        readonly public bool $typesOnly,
        readonly public int $sizeLimit = 0,
        readonly public int $timeLimit = 0,
    ) {
    }
}
