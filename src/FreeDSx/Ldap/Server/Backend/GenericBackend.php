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
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use Generator;

/**
 * No-op fallback backend: reads return empty, writes are rejected with UNWILLING_TO_PERFORM by the empty dispatcher.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class GenericBackend implements LdapBackendInterface
{
    public function search(
        SearchRequest $request,
        ControlBag $controls = new ControlBag(),
    ): EntryStream {
        return new EntryStream($this->yieldNothing());
    }

    /**
     * @return Generator<never>
     */
    private function yieldNothing(): Generator
    {
        yield from [];
    }

    public function get(Dn $dn): ?Entry
    {
        return null;
    }

    public function compare(
        Dn $dn,
        EqualityFilter $filter,
    ): bool {
        throw new OperationException(
            sprintf('No such object: %s', $dn->toString()),
            ResultCode::NO_SUCH_OBJECT,
        );
    }
}
