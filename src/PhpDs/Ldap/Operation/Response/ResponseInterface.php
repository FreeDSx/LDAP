<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Operation\Response;

use PhpDs\Ldap\Protocol\ProtocolElementInterface;

/**
 * Used to distinguish a protocol response element.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ResponseInterface extends ProtocolElementInterface
{
    const TYPE = [
        'BIND' => 1,
        'SEARCH_ENTRY' => 4,
        'SEARCH_DONE' => 5,
        'MODIFY' => 7,
        'ADD' => 9,
        'DELETE' => 11,
        'MODIFY_DN' => 13,
        'COMPARE' => 15,
        'SEARCH_REFERENCE' => 19,
        'EXTENDED' => 24,
        'INTERMEDIATE' => 25,
    ];
}
