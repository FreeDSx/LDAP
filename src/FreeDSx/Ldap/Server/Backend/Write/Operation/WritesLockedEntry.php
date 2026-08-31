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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation;

use Closure;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\RowLockableInterface;

/**
 * Opens the atomic write and takes the entry's row lock ahead of the body.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait WritesLockedEntry
{
    /**
     * @param Closure(): void $body
     * @throws OperationException
     */
    private function writeLocked(
        Dn $dn,
        Closure $body,
    ): void {
        $this->writer->write(function () use ($dn, $body): void {
            $this->lockForWrite($dn);
            $body();
        });
    }

    private function lockForWrite(Dn $dn): void
    {
        if (!$this->storage instanceof RowLockableInterface) {
            return;
        }

        $this->storage->lockForWrite($dn);
    }
}
