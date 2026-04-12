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
 * The core contract for an LDAP backend storage implementation.
 *
 * Implement this interface to provide a read-only backend.
 *
 * For a writable backend (add, delete, modify, rename) implement WritableLdapBackendInterface.
 *
 * The search() method returns a Generator that yields Entry objects. This library applies its own FilterEvaluator as a
 * final pass, so the backend may pre-filter for efficiency (e.g. translate to a SQL WHERE clause) or yield all
 * candidates in scope and let the framework filter.
 *
 * Each generator is scoped to a single client connection and a single paging session. It is paused between pages and
 * garbage-collected when the session ends, so no external paging state management is needed.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface LdapBackendInterface
{
    /**
     * Return an EntryStream for the given search context.
     *
     * The result wraps a lazy generator of candidate entries and a flag indicating whether the backend has already
     * applied the filter exactly. When EntryStream::$isPreFiltered is true, the caller may skip PHP-level
     * FilterEvaluator evaluation. Otherwise, all yielded entries are passed through FilterEvaluator as a final
     * correctness pass.
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
     * Evaluate a compare assertion against an entry.
     *
     * Return true if the attribute-value assertion matches, false if it does not.
     * Throw OperationException(NO_SUCH_OBJECT) if the entry does not exist.
     *
     * @throws OperationException
     */
    public function compare(
        Dn $dn,
        EqualityFilter $filter,
    ): bool;
}
