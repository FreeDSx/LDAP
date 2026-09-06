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

namespace FreeDSx\Ldap\Server\Backend\Auth\NameResolver;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;

/**
 * Resolves a bind name by searching for an entry where a given attribute equals the identity.
 *
 * Returns null when no entry matches. Throws when more than one entry matches to prevent
 * ambiguous identity resolution (RFC 4513 §5.1.3 implies a 1-to-1 mapping).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class AttributeSearchBindNameResolver implements BindNameResolverInterface
{
    public function __construct(
        private readonly string $baseDn = '',
        private readonly string $attribute = 'uid',
    ) {}

    /**
     * {@inheritDoc}
     *
     * @throws OperationException if more than one entry matches the identity.
     */
    public function resolve(
        string $name,
        ReadBackendInterface $backend,
    ): ?Entry {
        $request = (new SearchRequest(Filters::equal(
            $this->attribute,
            $name,
        )))
            ->base($this->baseDn)
            ->sizeLimit(2);

        $stream = $backend->search(
            $request,
            SubentryVisibility::Hide,
            new ControlBag(),
        );

        /** @var Entry[] $entries */
        $entries = iterator_to_array(
            $stream->entries(),
            false,
        );

        if (count($entries) > 1) {
            throw new OperationException(
                sprintf('Ambiguous SASL identity: multiple entries match on the "%s" attribute.', $this->attribute),
                ResultCode::OTHER,
            );
        }

        return $entries[0] ?? null;
    }
}
