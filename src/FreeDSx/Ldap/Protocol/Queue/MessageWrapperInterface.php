<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Socket\Queue\Buffer;

/**
 * Used to wrap / unwrap messages after ASN.1 encoding, or prior to ASN.1 decoding.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface MessageWrapperInterface
{
    /**
     * Wrap the message after it is encode to ASN.1.
     *
     * @param string $message
     * @return string
     */
    public function wrap(string $message): string;

    /**
     * Unwrap the message before it is decoded to ASN.1.
     *
     * @param string $message
     * @return Buffer
     */
    public function unwrap(string $message): Buffer;
}
