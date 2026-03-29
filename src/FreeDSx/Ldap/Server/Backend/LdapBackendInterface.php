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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use Generator;

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
     * Yield Entry objects matching (or potentially matching) the given search context.
     *
     * Applies FilterEvaluator after receiving each entry, so implementations may pre-filter (for efficiency) or yield
     * all in-scope candidates (for simplicity).
     *
     * @return Generator<Entry>
     */
    public function search(SearchContext $context): Generator;

    /**
     * Fetch a single entry by DN, or return null if it does not exist.
     */
    public function get(Dn $dn): ?Entry;
}
