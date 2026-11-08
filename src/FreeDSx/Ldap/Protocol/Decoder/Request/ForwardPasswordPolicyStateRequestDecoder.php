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

use DateTimeImmutable;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Asn1\Type\SetType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Validation\Syntax\UuidSyntaxValidator;
use Throwable;

use function count;
use function is_string;

/**
 * Decodes a replica's forwarded password policy state from its value.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ForwardPasswordPolicyStateRequestDecoder extends ExtendedRequestValueDecoder
{
    private const MALFORMED = 'The password policy forward request is malformed.';

    public function __construct(private UuidSyntaxValidator $uuids) {}

    public function decode(
        ?string $value,
        DecodeContext $context,
    ): ForwardPasswordPolicyStateRequest {
        $request = $this->decodeValue(
            $value,
            $context,
        );
        $childCount = $request instanceof SequenceType
            ? count($request->getChildren())
            : 0;
        if (!($request instanceof SequenceType) || $childCount < 2 || $childCount > 3) {
            throw new ProtocolException(self::MALFORMED);
        }

        $entryUuid = $request->getChild(0);
        $failureTimes = $request->getChild(1);
        if (!($entryUuid instanceof OctetStringType && $failureTimes instanceof SetType)) {
            throw new ProtocolException(self::MALFORMED);
        }
        if (!$this->uuids->isValid($entryUuid->getValue())) {
            throw new ProtocolException('The password policy forward request has an invalid entry UUID.');
        }

        return new ForwardPasswordPolicyStateRequest(
            $entryUuid->getValue(),
            $this->failureTimes($failureTimes),
            $this->lastSuccess(
                $request->getChild(2),
                $context,
            ),
        );
    }

    /**
     * @return list<DateTimeImmutable>
     * @throws ProtocolException
     */
    private function failureTimes(SetType $failureTimes): array
    {
        $values = [];

        foreach ($failureTimes->getChildren() as $value) {
            if (!$value instanceof OctetStringType) {
                throw new ProtocolException(self::MALFORMED);
            }

            $values[] = $this->time($value->getValue());
        }

        return $values;
    }

    /**
     * @param AbstractType<mixed>|null $lastSuccess
     * @throws EncoderException
     * @throws ProtocolException
     */
    private function lastSuccess(
        ?AbstractType $lastSuccess,
        DecodeContext $context,
    ): ?DateTimeImmutable {
        if ($lastSuccess === null) {
            return null;
        }
        if (!$this->isLastSuccess($lastSuccess)) {
            throw new ProtocolException(self::MALFORMED);
        }

        $value = $lastSuccess instanceof IncompleteType
            ? $context->complete(
                $lastSuccess,
                AbstractType::TAG_TYPE_OCTET_STRING,
            )
            : $lastSuccess;

        return $this->time($value->getValue());
    }

    /**
     * @param AbstractType<mixed> $component
     */
    private function isLastSuccess(AbstractType $component): bool
    {
        return $component->getTagClass() === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC
            && $component->getTagNumber() === 0;
    }

    /**
     * @throws ProtocolException
     */
    private function time(mixed $value): DateTimeImmutable
    {
        if (!is_string($value)) {
            throw new ProtocolException('The password policy forward request has an invalid time value.');
        }

        try {
            return GeneralizedTime::parse($value);
        } catch (Throwable) {
            throw new ProtocolException('The password policy forward request has an invalid time value.');
        }
    }
}
