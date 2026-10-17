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

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
use FreeDSx\Ldap\Control\SubtreeDeleteProgressControl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\ResponseInterface;

/**
 * The LDAP Message envelope PDU. This represents a message as a response from LDAP.
 *
 * @see LdapMessage
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapMessageResponse extends LdapMessage
{
    public function __construct(
        int $messageId,
        private ResponseInterface $response,
        Control ...$controls,
    ) {
        parent::__construct(
            $messageId,
            ...$controls,
        );
    }

    public function getResponse(): ResponseInterface|LdapResult
    {
        return $this->response;
    }

    /**
     * @return AbstractType<mixed>
     */
    protected function getOperationAsn1(): AbstractType
    {
        return $this->response->toAsn1();
    }

    protected static function controlFromAsn1(SequenceType $control): Control
    {
        return match ($control->getChild(0)?->getValue()) {
            Control::OID_PWD_POLICY => PwdPolicyResponseControl::fromAsn1($control),
            Control::OID_PRE_READ => PreReadResponseControl::fromAsn1($control),
            Control::OID_POST_READ => PostReadResponseControl::fromAsn1($control),
            Control::OID_SUBTREE_DELETE_PROGRESS => SubtreeDeleteProgressControl::fromAsn1($control),
            default => parent::controlFromAsn1($control),
        };
    }
}
