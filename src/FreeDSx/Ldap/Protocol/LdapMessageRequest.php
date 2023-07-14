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
use FreeDSx\Ldap\Operation\Request\RequestInterface;

/**
 * The LDAP Message envelope PDU. This represents a message as a request to LDAP.
 *
 * @see LdapMessage
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapMessageRequest extends LdapMessage
{
    public function __construct(
        int $messageId,
        private readonly RequestInterface $request,
        Control ...$controls
    ) {
        parent::__construct(
            $messageId,
            ...$controls
        );
    }

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }

    protected function getOperationAsn1(): AbstractType
    {
        return $this->request->toAsn1();
    }
}
