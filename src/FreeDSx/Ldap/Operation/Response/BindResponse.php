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

namespace FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\LdapResult;

/**
 * RFC 4511 Section 4.2.2
 *
 * BindResponse ::= [APPLICATION 1] SEQUENCE {
 *     COMPONENTS OF LDAPResult,
 *     serverSaslCreds    [7] OCTET STRING OPTIONAL }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class BindResponse extends LdapResult
{
    protected int $tagNumber = 1;

    private ?string $saslCreds;

    public function __construct(
        LdapResult $result,
        ?string $saslCreds = null
    ) {
        $this->saslCreds = $saslCreds;
        parent::__construct(
            $result->getResultCode(),
            $result->getDn()->toString(),
            $result->getDiagnosticMessage(),
            ...$result->getReferrals()
        );
    }

    public function getSaslCredentials(): ?string
    {
        return $this->saslCreds;
    }

    /**
     * @throws ProtocolException
     */
    public function toAsn1(): SequenceType
    {
        /** @var SequenceType $response */
        $response = parent::toAsn1();

        if ($this->saslCreds !== null) {
            $response->addChild(Asn1::context(
                tagNumber: 7,
                type: Asn1::octetString($this->saslCreds)
            ));
        }

        return $response;
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        [$resultCode, $dn, $diag, $ref] = self::parseResultData($type);
        $saslCreds = null;

        foreach ($type->getChildren() as $child) {
            if ($child->getTagNumber() === 7 && $child->getTagClass() === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
                $saslCreds = $child->getValue();
                break;
            }
        }

        return new static(
            new LdapResult(
                $resultCode,
                $dn,
                $diag,
                ...$ref,
            ),
            $saslCreds
        );
    }
}
