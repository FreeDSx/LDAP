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
use PhpDs\Ldap\Operation\LdapResult;
use PhpDs\Ldap\Operation\Response\ResponseInterface;

/**
 * The LDAP Message envelope PDU. This represents a message as a response from LDAP.
 *
 * @see LdapMessage
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapMessageResponse extends LdapMessage
{
    /**
     * @var ResponseInterface
     */
    protected $response;

    /**
     * @param int $messageId
     * @param ResponseInterface $response
     * @param Control[] ...$controls
     */
    public function __construct(int $messageId, ResponseInterface $response, Control ...$controls)
    {
        $this->response = $response;
        parent::__construct($messageId, ...$controls);
    }

    /**
     * @return ResponseInterface|LdapResult
     */
    public function getResponse() : ResponseInterface
    {
        return $this->response;
    }

    /**
     * @return AbstractType
     */
    protected function getOperationAsn1(): AbstractType
    {
        return $this->response->toAsn1();
    }
}
