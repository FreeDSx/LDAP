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

namespace FreeDSx\Ldap\Operation\Request;

use DateTimeImmutable;
use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Asn1\Type\SetType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Validation\Syntax\UuidSyntaxValidator;
use Throwable;

use function array_map;
use function array_values;
use function count;
use function is_string;

/**
 * FreeDSx-private extended op forwarding a replica's observed password-policy bind state to the primary.
 *
 * The primary unions the failure times into the entry and, bounded by the observed success, derives lockout itself; it
 * carries nothing but bind state, so it cannot express any other modification.
 *
 * ForwardPasswordPolicyStateValue ::= SEQUENCE {
 *     entryUuid     OCTET STRING,
 *     failureTimes  SET OF OCTET STRING,
 *     lastSuccess   [0] OCTET STRING OPTIONAL }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ForwardPasswordPolicyStateRequest extends ExtendedRequest
{
    /**
     * @var list<DateTimeImmutable>
     */
    private array $failureTimes;

    /**
     * @param list<DateTimeImmutable> $failureTimes Values the primary unions into the entry.
     * @param DateTimeImmutable|null $lastSuccess Latest observed successful bind, bounding which failures it clears.
     */
    public function __construct(
        private readonly string $entryUuid,
        array $failureTimes = [],
        private readonly ?DateTimeImmutable $lastSuccess = null,
    ) {
        $this->failureTimes = array_values($failureTimes);
        parent::__construct(ExtendedRequest::OID_PPOLICY_STATE_FORWARD);
    }

    public function getEntryUuid(): string
    {
        return $this->entryUuid;
    }

    /**
     * @return list<DateTimeImmutable>
     */
    public function getFailureTimes(): array
    {
        return $this->failureTimes;
    }

    public function getLastSuccess(): ?DateTimeImmutable
    {
        return $this->lastSuccess;
    }

    public function toAsn1(): SequenceType
    {
        $sequence = Asn1::sequence(
            Asn1::octetString($this->entryUuid),
            Asn1::setOf(...array_map(
                static fn(DateTimeImmutable $time): OctetStringType
                    => Asn1::octetString(GeneralizedTime::formatWithFraction($time)),
                $this->failureTimes,
            )),
        );

        if ($this->lastSuccess !== null) {
            $sequence->addChild(Asn1::context(
                0,
                Asn1::octetString(GeneralizedTime::format($this->lastSuccess)),
            ));
        }

        $this->requestValue = $sequence;

        return parent::toAsn1();
    }

    /**
     * {@inheritDoc}
     *
     * @param AbstractType<mixed> $type
     * @throws EncoderException
     * @throws PartialPduException
     * @throws ProtocolException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $request = self::decodeEncodedValue($type);
        $childCount = $request instanceof SequenceType
            ? count($request->getChildren())
            : 0;
        if (!($request instanceof SequenceType) || $childCount < 2 || $childCount > 3) {
            throw new ProtocolException('The password policy forward request is malformed.');
        }

        $entryUuid = $request->getChild(0);
        $failureTimes = $request->getChild(1);
        if (!($entryUuid instanceof OctetStringType && $failureTimes instanceof SetType)) {
            throw new ProtocolException('The password policy forward request is malformed.');
        }
        if (!(new UuidSyntaxValidator())->isValid($entryUuid->getValue())) {
            throw new ProtocolException('The password policy forward request has an invalid entry UUID.');
        }

        return new static(
            $entryUuid->getValue(),
            self::parseFailureTimes($failureTimes),
            self::parseLastSuccess($request->getChild(2)),
        );
    }

    /**
     * @return list<DateTimeImmutable>
     * @throws ProtocolException
     */
    private static function parseFailureTimes(SetType $failureTimes): array
    {
        $values = [];

        foreach ($failureTimes->getChildren() as $value) {
            if (!$value instanceof OctetStringType) {
                throw new ProtocolException('The password policy forward request is malformed.');
            }

            $values[] = self::parseTime($value->getValue());
        }

        return $values;
    }

    /**
     * @param AbstractType<mixed>|null $lastSuccess
     * @throws EncoderException
     * @throws ProtocolException
     */
    private static function parseLastSuccess(?AbstractType $lastSuccess): ?DateTimeImmutable
    {
        if ($lastSuccess === null) {
            return null;
        }
        if ($lastSuccess->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC || $lastSuccess->getTagNumber() !== 0) {
            throw new ProtocolException('The password policy forward request is malformed.');
        }

        $value = $lastSuccess instanceof IncompleteType
            ? (new LdapEncoder())->complete($lastSuccess, AbstractType::TAG_TYPE_OCTET_STRING)
            : $lastSuccess;

        return self::parseTime($value->getValue());
    }

    /**
     * @throws ProtocolException
     */
    private static function parseTime(mixed $value): DateTimeImmutable
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
