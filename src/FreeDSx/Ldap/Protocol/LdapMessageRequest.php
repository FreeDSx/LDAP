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
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\Request\RequestInterface;

/**
 * The LDAP Message envelope PDU. This represents a message as a request to LDAP.
 *
 * @see LdapMessage
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapMessageRequest extends LdapMessage
{
    /**
     * The protocolOp tags a client sends, keyed to the request each decodes into.
     *
     * @var array<int, class-string<RequestInterface>>
     */
    private const PROTOCOL_OPS = [
        0 => Request\BindRequest::class,
        2 => Request\UnbindRequest::class,
        3 => Request\SearchRequest::class,
        6 => Request\ModifyRequest::class,
        8 => Request\AddRequest::class,
        10 => Request\DeleteRequest::class,
        12 => Request\ModifyDnRequest::class,
        14 => Request\CompareRequest::class,
        16 => Request\AbandonRequest::class,
        23 => Request\ExtendedRequest::class,
    ];

    public function __construct(
        int $messageId,
        private readonly RequestInterface $request,
        Control ...$controls,
    ) {
        parent::__construct(
            $messageId,
            ...$controls,
        );
    }

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }

    /**
     * @return AbstractType<mixed>
     */
    protected function getOperationAsn1(): AbstractType
    {
        return $this->request->toAsn1();
    }

    protected static function protocolOps(): array
    {
        return self::PROTOCOL_OPS;
    }
}
