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

use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;

/**
 * Raw persistence contract; LDAP semantics live in the read backend and write handlers above it. Dn parameters are always normalised (lowercased).
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface EntryStorageInterface extends
    ReadEntryInterface,
    ListEntryInterface,
    WriteEntryInterface,
    TransactionalWriteInterface {}
