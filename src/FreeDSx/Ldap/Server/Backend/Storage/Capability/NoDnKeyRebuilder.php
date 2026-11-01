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

/**
 * Stands in for storage whose DN keys never outlive the process that derived them.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class NoDnKeyRebuilder implements DnKeyRebuilderInterface
{
    public function rebuild(): void {}
}
