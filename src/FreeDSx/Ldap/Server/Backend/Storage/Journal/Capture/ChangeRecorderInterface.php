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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Keeps a record of what a write changed.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChangeRecorderInterface
{
    public function recordAdd(
        Entry $entry,
        WriteContext $context,
    ): void;

    public function recordModify(
        Entry $entry,
        WriteContext $context,
    ): void;

    public function recordModRdn(
        Entry $entry,
        Dn $previousDn,
        WriteContext $context,
    ): void;

    public function recordDelete(
        Entry $entry,
        WriteContext $context,
    ): void;

    /**
     * Whether anything is kept at all.
     */
    public function records(): bool;
}
