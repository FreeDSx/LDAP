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

namespace FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;

/**
 * Implemented by access control classes or matchers that need a backend injected at startup.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface BackendAwareInterface
{
    public function setBackend(ReadBackendInterface $backend): void;
}
