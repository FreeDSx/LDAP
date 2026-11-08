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
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Asn1\Type\SetOfType;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;

use function array_values;

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
        $failureTimes = [];
        foreach ($this->failureTimes as $time) {
            $failureTimes[] = Asn1::octetString(GeneralizedTime::formatWithFraction($time));
        }

        $sequence = Asn1::sequence(
            Asn1::octetString($this->entryUuid),
            SetOfType::fromChildren($failureTimes),
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
}
