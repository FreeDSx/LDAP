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
use FreeDSx\Ldap\Control\Control;
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
    private ResponseInterface $response;

    public function __construct(
        int $messageId,
        ResponseInterface $response,
        Control ...$controls
    ) {
        $this->response = $response;
        parent::__construct(
            $messageId,
            ...$controls
        );
    }

    public function getResponse(): ResponseInterface|LdapResult
    {
        return $this->response;
    }

    protected function getOperationAsn1(): AbstractType
    {
        return $this->response->toAsn1();
    }
}
