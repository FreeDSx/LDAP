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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;

/**
 * Follows an alias to the entry it names, including aliases naming further aliases (RFC 4511 4.5.1.3).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AliasResolver
{
    /**
     * Bounds the walk, since RFC 4511 4.5.1.3 requires loop detection to prevent denial of service.
     */
    private const MAX_HOPS = 10;

    public function __construct(private EntryStorageInterface $storage) {}

    /**
     * The entry an alias chain ends at, or null when the name is absent or names no alias, since neither needs
     * anything dereferenced.
     *
     * @throws OperationException
     */
    public function resolve(Dn $dn): ?Entry
    {
        $current = $this->storage->find($dn->normalize());
        if ($current === null || !$this->isAlias($current)) {
            return null;
        }

        $hops = 0;
        while ($this->isAlias($current)) {
            if (++$hops > self::MAX_HOPS) {
                throw new OperationException(
                    'The alias chain is too long, or loops.',
                    ResultCode::ALIAS_PROBLEM,
                );
            }
            $current = $this->storage->find($this->aliasedName($current)->normalize())
                ?? throw new OperationException(
                    'An alias names an entry that does not exist.',
                    ResultCode::ALIAS_PROBLEM,
                );
        }

        return $current;
    }

    /**
     * RFC 4512: an entry whose objectClass includes "alias".
     */
    public function isAlias(Entry $entry): bool
    {
        return $entry
            ->get(AttributeTypeOid::NAME_OBJECT_CLASS)
            ?->has(
                ObjectClassOid::NAME_ALIAS,
                caseSensitive: false,
            ) === true;
    }

    /**
     * @throws OperationException
     */
    private function aliasedName(Entry $alias): Dn
    {
        $value = $alias->get(AttributeTypeOid::NAME_ALIASED_OBJECT_NAME)?->firstValue();

        if ($value === null || $value === '') {
            throw new OperationException(
                'An alias carries no aliased object name.',
                ResultCode::ALIAS_PROBLEM,
            );
        }

        try {
            return new Dn($value);
        } catch (InvalidArgumentException) {
            throw new OperationException(
                'An alias names an entry that is not a valid DN.',
                ResultCode::ALIAS_PROBLEM,
            );
        }
    }
}
