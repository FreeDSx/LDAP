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

namespace FreeDSx\Ldap\Server\Backend\Storage\Capability;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;

/**
 * Stands in for storage that serializes its writes instead of locking rows, so a lock is never absent.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class UnlockedRows implements RowLockableInterface
{
    public function __construct(private ReadEntryInterface $storage) {}

    public function lockForWrite(Dn $dn): void {}

    /**
     * Answers from the entry alone, which is sound only because nothing else may be writing concurrently.
     */
    public function lockForReference(Dn $dn): bool
    {
        return $this->storage->exists($dn);
    }
}
