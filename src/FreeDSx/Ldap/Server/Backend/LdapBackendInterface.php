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

/**
 * Read-only LDAP backend contract; implement WritableLdapBackendInterface for full CRUD.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface LdapBackendInterface
{
    /**
     * Set EntryStream::$isPreFiltered to true when the backend has applied the filter exactly; otherwise FilterEvaluator re-checks each yielded entry.
     */
    public function search(
        SearchRequest $request,
        ControlBag $controls = new ControlBag(),
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
}
