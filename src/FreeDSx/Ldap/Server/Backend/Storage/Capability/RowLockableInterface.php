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

/**
 * A storage adapter that can take an exclusive per-entry write lock inside an atomic block.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface RowLockableInterface
{
    /**
     * Acquire an exclusive lock on the entry within the current atomic block; released when it commits or rolls back.
     */
    public function lockForWrite(Dn $dn): void;
}
