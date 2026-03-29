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
 * A no-op backend used when no backend has been configured via LdapServer::useBackend().
 *
 * Read operations return empty / false results. Write operations are handled by
 * an empty WriteOperationDispatcher, which returns UNWILLING_TO_PERFORM.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class GenericBackend implements LdapBackendInterface
{
    public function search(SearchContext $context): Generator
    {
        yield from [];
    }

    public function get(Dn $dn): ?Entry
    {
        return null;
    }
}
