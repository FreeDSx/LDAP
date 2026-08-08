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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;

/**
 * Read-side backend contract that read-only consumers depend on.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface LdapBackendInterface
{
    /**
     * @param SubentryVisibility $subentries Which entry population is in scope; callers state it, as no default is safe for all.
     * @param ?SearchLimits $effectiveLimits Per-request effective limits (time/lookthrough); null uses backend defaults.
     */
    public function search(
        SearchRequest $request,
        SubentryVisibility $subentries,
        ControlBag $controls = new ControlBag(),
        ?SearchLimits $effectiveLimits = null,
    ): EntryStream;

    /**
     * Fetch a single entry by DN, or return null if it does not exist.
     */
    public function get(Dn $dn): ?Entry;

    /**
     * Evaluate a compare assertion; throws OperationException(NO_SUCH_OBJECT) when the entry is missing.
     *
     * @throws OperationException
     */
    public function compare(
        Dn $dn,
        EqualityFilter $filter,
    ): bool;

    /**
     * Normalised DNs the backend hosts. Advertised by the server as RootDSE namingContexts.
     *
     * @return list<Dn>
     */
    public function namingContexts(): array;
}
