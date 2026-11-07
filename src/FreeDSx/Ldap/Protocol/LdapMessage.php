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

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceOfType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;

use function count;

/**
 * The LDAP Message envelope (PDU). RFC 4511, 4.1.1
 *
 * LDAPMessage ::= SEQUENCE {
 *     messageID       MessageID,
 *     protocolOp      CHOICE {
 *         bindRequest           BindRequest,
 *         bindResponse          BindResponse,
 *         unbindRequest         UnbindRequest,
 *         searchRequest         SearchRequest,
 *         searchResEntry        SearchResultEntry,
 *         searchResDone         SearchResultDone,
 *         searchResRef          SearchResultReference,
 *         modifyRequest         ModifyRequest,
 *         modifyResponse        ModifyResponse,
 *         addRequest            AddRequest,
 *         addResponse           AddResponse,
 *         delRequest            DelRequest,
 *         delResponse           DelResponse,
 *         modDNRequest          ModifyDNRequest,
 *         modDNResponse         ModifyDNResponse,
 *         compareRequest        CompareRequest,
 *         compareResponse       CompareResponse,
 *         abandonRequest        AbandonRequest,
 *         extendedReq           ExtendedRequest,
 *         extendedResp          ExtendedResponse,
 *         ...,
 *         intermediateResponse  IntermediateResponse },
 *     controls       [0] Controls OPTIONAL }
 *
 * MessageID ::= INTEGER (0 ..  maxInt)
 *
 * maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract class LdapMessage implements ProtocolElementInterface
{
    /**
     * The upper bound every RFC 4511 INTEGER (0 .. maxInt) field shares.
     */
    public const MAX_INT = 2147483647;

    private ControlBag $controls;

    public function __construct(
        private readonly int $messageId,
        Control ...$controls,
    ) {
        $this->controls = new ControlBag(...$controls);
    }

    public function getMessageId(): int
    {
        return $this->messageId;
    }

    /**
     * Get the controls for this specific message.
     */
    public function controls(): ControlBag
    {
        return $this->controls;
    }

    /**
     * @throws EncoderException
     */
    public function toAsn1(): SequenceType
    {
        $asn1 = Asn1::sequence(
            Asn1::integer($this->messageId),
            $this->getOperationAsn1(),
        );

        if (count($this->controls->toArray()) !== 0) {
            /** @var SequenceOfType $controls */
            $controls = Asn1::context(
                tagNumber: 0,
                type: Asn1::sequenceOf(),
            );
            foreach ($this->controls->toArray() as $control) {
                $controls->addChild($control->toAsn1());
            }
            $asn1->addChild($controls);
        }

        return $asn1;
    }

    /**
     * @return AbstractType<mixed>
     */
    abstract protected function getOperationAsn1(): AbstractType;
}
