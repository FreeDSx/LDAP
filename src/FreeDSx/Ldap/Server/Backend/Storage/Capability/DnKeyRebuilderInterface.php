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

use FreeDSx\Ldap\Exception\InvalidDnSyntaxException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnKeyCollisionException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;

/**
 * Storage that keeps a normalized key beside each stored DN; a change to DN normalization leaves those keys stale.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface DnKeyRebuilderInterface
{
    /**
     * Recompute every stored DN key from the DN it was derived from, in the caller's transaction or one of its own.
     *
     * @throws DnKeyCollisionException when two entries' DNs now normalize to the same key
     * @throws DnTooLongException when a rebuilt key exceeds what the storage holds
     * @throws InvalidDnSyntaxException when a stored DN no longer parses
     */
    public function rebuild(): void;
}
