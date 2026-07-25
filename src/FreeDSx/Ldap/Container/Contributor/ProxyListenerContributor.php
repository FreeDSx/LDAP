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
 * A proxy serves no local directory, so it has nothing to reset per fork and carries nothing across a reload.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ProxyListenerContributor implements ListenerContributorInterface
{
    public function forkResettable(): ?ResettableInterface
    {
        return null;
    }

    public function reloadInstances(): array
    {
        return [];
    }
}
