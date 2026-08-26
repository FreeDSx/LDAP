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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;

/**
 * Tries each resolver in order, returning the first non-null result.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class BindNameResolverChain implements BindNameResolverInterface
{
    /**
     * @param BindNameResolverInterface[] $resolvers
     */
    public function __construct(private array $resolvers) {}

    public function resolve(
        string $name,
        ReadBackendInterface $backend,
    ): ?Entry {
        foreach ($this->resolvers as $resolver) {
            $entry = $resolver->resolve(
                $name,
                $backend,
            );

            if ($entry !== null) {
                return $entry;
            }
        }

        return null;
    }
}
