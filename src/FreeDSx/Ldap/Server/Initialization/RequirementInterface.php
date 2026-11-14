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

namespace FreeDSx\Ldap\Server\Initialization;

use FreeDSx\Ldap\Exception\RuntimeException;

/**
 * What the configuration must meet for the server to start with it or adopt it on a reload.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface RequirementInterface
{
    /**
     * @throws RuntimeException when the server cannot run with the configuration.
     */
    public function assertMet(): void;
}
