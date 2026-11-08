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
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Operation\LdapResult;

/**
 * RFC 3062. A Modify Password Response.
 *
 * PasswdModifyResponseValue ::= SEQUENCE {
 *     genPasswd       [0]     OCTET STRING OPTIONAL }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PasswordModifyResponse extends ExtendedResponse
{
    private ?string $generatedPassword;

    public function __construct(
        LdapResult $result,
        ?string $generatedPassword = null,
    ) {
        $this->generatedPassword = $generatedPassword;
        parent::__construct($result);
    }

    public function getGeneratedPassword(): ?string
    {
        return $this->generatedPassword;
    }

    public function toAsn1(): SequenceType
    {
        if ($this->generatedPassword !== null) {
            $this->responseValue = Asn1::sequence(Asn1::context(
                tagNumber: 0,
                type: Asn1::octetString($this->generatedPassword),
            ));
        }

        return parent::toAsn1();
    }
}
