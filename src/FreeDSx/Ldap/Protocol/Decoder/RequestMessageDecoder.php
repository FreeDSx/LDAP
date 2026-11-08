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

namespace FreeDSx\Ldap\Protocol\Decoder;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\ProtocolElementInterface;

/**
 * Decodes each message a client sends into the request it carries and its controls.
 *
 * @extends MessageDecoder<RequestInterface, LdapMessageRequest>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class RequestMessageDecoder extends MessageDecoder
{
    protected function message(
        int $messageId,
        ProtocolElementInterface $operation,
        Control ...$controls,
    ): LdapMessageRequest {
        return new LdapMessageRequest(
            $messageId,
            $operation,
            ...$controls,
        );
    }
}
