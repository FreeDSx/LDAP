<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Socket\Queue\Asn1MessageQueue;
use FreeDSx\Socket\Queue\Message;

class LdapResponseQueue extends Asn1MessageQueue
{
    /**
     * {@inheritdoc}
     */
    public function constructMessage(Message $message, ?int $id = null)
    {
        return LdapMessageResponse::fromAsn1($message->getMessage());
    }
}
