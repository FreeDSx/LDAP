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
use FreeDSx\Ldap\Operation\Response\ResponseInterface;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ProtocolElementInterface;

/**
 * Decodes each message a server sends into the response it carries and its controls.
 *
 * @extends MessageDecoder<ResponseInterface, LdapMessageResponse>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ResponseMessageDecoder extends MessageDecoder
{
    protected function message(
        int $messageId,
        ProtocolElementInterface $operation,
        Control ...$controls,
    ): LdapMessageResponse {
        return new LdapMessageResponse(
            $messageId,
            $operation,
            ...$controls,
        );
    }
}
