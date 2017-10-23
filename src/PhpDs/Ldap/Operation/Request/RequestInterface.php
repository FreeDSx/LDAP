<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Operation\Request;

use PhpDs\Ldap\Protocol\ProtocolElementInterface;

/**
 * Used to distinguish a protocol request element.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface RequestInterface extends ProtocolElementInterface
{
    const TYPE = [
        'BIND' => 0,
        'UNBIND' => 2,
        'SEARCH' => 3,
        'MODIFY' => 4,
        'ADD' => 8,
        'DELETE' => 10,
        'MODIFY_DN' => 12,
        'COMPARE' => 14,
        'EXTENDED' => 23,
    ];
}
