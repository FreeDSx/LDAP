<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Protocol;

use PhpDs\Ldap\Asn1\Type\AbstractType;
use PhpDs\Ldap\Control\Control;
use PhpDs\Ldap\Operation\Request\RequestInterface;

/**
 * The LDAP Message envelope PDU. This represents a message as a request to LDAP.
 *
 * @see LdapMessage
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapMessageRequest extends LdapMessage
{
    /**
     * @var RequestInterface
     */
    protected $request;

    /**
     * @param int $messageId
     * @param RequestInterface $request
     * @param Control[] ...$controls
     */
    public function __construct(int $messageId, RequestInterface $request, Control ...$controls)
    {
        $this->request = $request;
        parent::__construct($messageId, ...$controls);
    }

    /**
     * @return RequestInterface
     */
    public function getRequest() : RequestInterface
    {
        return $this->request;
    }

    /**
     * @return AbstractType
     */
    protected function getOperationAsn1(): AbstractType
    {
        return $this->request->toAsn1();
    }
}
