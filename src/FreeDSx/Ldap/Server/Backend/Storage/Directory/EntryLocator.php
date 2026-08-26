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

namespace FreeDSx\Ldap\Server\Backend\Storage\Directory;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;

use function sprintf;

/**
 * Locates an entry, or raises the result code its absence or presence calls for.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryLocator
{
    public function __construct(private EntryStorageInterface $storage) {}

    /**
     * @throws OperationException
     */
    public function findOrFail(Dn $dn): Entry
    {
        $entry = $this->storage->find($dn);

        if ($entry === null) {
            $this->throwNoSuchObject($dn);
        }

        return $entry;
    }

    /**
     * @throws OperationException
     */
    public function throwNoSuchObject(Dn $dn): never
    {
        throw new OperationException(
            sprintf('No such object: %s', $dn->toString()),
            ResultCode::NO_SUCH_OBJECT,
            null,
            $this->findMatchedDn($dn),
        );
    }

    /**
     * @throws OperationException
     */
    public function throwEntryAlreadyExists(Dn $dn): never
    {
        throw new OperationException(
            sprintf('Entry already exists: %s', $dn->toString()),
            ResultCode::ENTRY_ALREADY_EXISTS,
        );
    }

    /**
     * Walks up the parent chain to find the deepest ancestor that exists in the DIT (RFC 4511 §4.1.9).
     */
    private function findMatchedDn(Dn $dn): ?Dn
    {
        try {
            $current = $dn->getParent();

            while ($current !== null) {
                if ($this->storage->exists($current->normalize())) {
                    return $current;
                }

                $current = $current->getParent();
            }
        } catch (InvalidArgumentException) {
            // DN has malformed components — no matched ancestor can be determined.
        }

        return null;
    }
}
