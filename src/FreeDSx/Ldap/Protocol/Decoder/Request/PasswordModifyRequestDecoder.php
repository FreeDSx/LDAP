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

namespace FreeDSx\Ldap\Protocol\Decoder\Request;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function is_string;

/**
 * Decodes a password modify request (RFC 3062) from its value.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PasswordModifyRequestDecoder extends ExtendedRequestValueDecoder
{
    private const MALFORMED = 'The password modify request is malformed.';

    public function decode(
        ?string $value,
        DecodeContext $context,
    ): PasswordModifyRequest {
        $request = $this->decodeValue(
            $value,
            $context,
        );
        if ($request === null) {
            return new PasswordModifyRequest();
        }
        if (!($request instanceof SequenceType)) {
            throw new ProtocolException(self::MALFORMED);
        }

        $userIdentity = null;
        $oldPasswd = null;
        $newPasswd = null;
        foreach ($request->getChildren() as $field) {
            if ($field->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
                throw new ProtocolException(self::MALFORMED);
            }
            if ($field->getTagNumber() === 0) {
                $userIdentity = $field;
            } elseif ($field->getTagNumber() === 1) {
                $oldPasswd = $field;
            } elseif ($field->getTagNumber() === 2) {
                $newPasswd = $field;
            } else {
                // RFC 3062 3: a field the server does not recognize must leave the password unchanged.
                throw new ProtocolException(self::MALFORMED);
            }
        }

        return new PasswordModifyRequest(
            $this->fieldValue($userIdentity),
            $this->fieldValue($oldPasswd),
            $this->fieldValue($newPasswd),
        );
    }

    /**
     * @param AbstractType<mixed>|null $field
     * @throws ProtocolException
     */
    private function fieldValue(?AbstractType $field): ?string
    {
        $value = $field?->getValue();
        if ($value !== null && !is_string($value)) {
            throw new ProtocolException(self::MALFORMED);
        }

        return $value;
    }
}
