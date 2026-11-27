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

use function array_slice;
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

    private const TAG_LAST_SUCCESS = 0;

    private const TAG_PASSWORD_VERSION = 1;

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
        if (!($request instanceof SequenceType) || $childCount < 2 || $childCount > 4) {
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

        $optional = $this->optionalTimes(
            array_slice(
                $request->getChildren(),
                2,
            ),
            $context,
        );

        return new ForwardPasswordPolicyStateRequest(
            $entryUuid->getValue(),
            $this->failureTimes($failureTimes),
            $optional[self::TAG_LAST_SUCCESS] ?? null,
            $optional[self::TAG_PASSWORD_VERSION] ?? null,
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
     * The optional components keyed by context tag, each known tag at most once and in the order the sequence defines.
     *
     * @param array<AbstractType<mixed>> $components
     * @return array<int, DateTimeImmutable>
     * @throws EncoderException
     * @throws ProtocolException
     */
    private function optionalTimes(
        array $components,
        DecodeContext $context,
    ): array {
        $times = [];
        $previous = -1;

        foreach ($components as $component) {
            $tag = $this->optionalTagOf(
                $component,
                $previous,
            );
            $times[$tag] = $this->contextTime(
                $component,
                $context,
            );
            $previous = $tag;
        }

        return $times;
    }

    /**
     * @param AbstractType<mixed> $component
     * @throws ProtocolException when the component is not a known optional one following $previous.
     */
    private function optionalTagOf(
        AbstractType $component,
        int $previous,
    ): int {
        $tag = $component->getTagNumber();

        if ($component->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
            throw new ProtocolException(self::MALFORMED);
        }
        if (!is_int($tag) || $tag <= $previous || $tag > self::TAG_PASSWORD_VERSION) {
            throw new ProtocolException(self::MALFORMED);
        }

        return $tag;
    }

    /**
     * @param AbstractType<mixed> $component
     * @throws EncoderException
     * @throws ProtocolException
     */
    private function contextTime(
        AbstractType $component,
        DecodeContext $context,
    ): DateTimeImmutable {
        $value = $component instanceof IncompleteType
            ? $context->complete(
                $component,
                AbstractType::TAG_TYPE_OCTET_STRING,
            )
            : $component;

        return $this->time($value->getValue());
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
