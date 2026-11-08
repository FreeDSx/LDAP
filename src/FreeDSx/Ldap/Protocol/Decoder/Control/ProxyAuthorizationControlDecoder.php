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

namespace FreeDSx\Ldap\Protocol\Decoder\Control;

use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\ProxyAuthorizationControl;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

/**
 * Decodes a proxied authorization control (RFC 4370).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ProxyAuthorizationControlDecoder implements ControlDecoderInterface
{
    /**
     * @throws ProtocolException
     */
    public function decode(
        SequenceType $control,
        DecodeContext $context,
    ): ProxyAuthorizationControl {
        $fields = ControlFields::of($control);

        // RFC 4370 3: the value is present even for an anonymous identity.
        if ($fields->value === null) {
            throw new ProtocolException('The proxied authorization control must have a value.');
        }

        try {
            return new ProxyAuthorizationControl(
                AuthzId::fromString($fields->value),
                $fields->criticality,
            );
        } catch (InvalidArgumentException) {
            // Preserve a malformed value so it surfaces as an authorization denial rather than a decode failure.
            return ProxyAuthorizationControl::unparsed(
                $fields->value,
                $fields->criticality,
            );
        }
    }
}
