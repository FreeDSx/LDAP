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

namespace FreeDSx\Ldap\Container\Contributor;

use FreeDSx\Ldap\Server\Backend\ResettableInterface;

/**
 * Server-type-specific pieces the shared listener provider cannot derive itself: a per-fork resettable and the live
 * services to carry across a reload; a proxy contributes neither.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ListenerContributorInterface
{
    /**
     * The service the forking runner resets in each child, or null when the server type has nothing to reset.
     */
    public function forkResettable(): ?ResettableInterface;

    /**
     * Live services to seed into the reloaded container so their state survives the reload.
     *
     * @return array<class-string, object>
     */
    public function reloadInstances(): array;
}
