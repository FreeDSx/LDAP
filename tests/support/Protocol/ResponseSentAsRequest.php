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

namespace Tests\Support\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Response\ResponseInterface;

/**
 * Sends a response operation to a server, which only ever expects requests.
 */
final readonly class ResponseSentAsRequest implements RequestInterface
{
    public function __construct(private ResponseInterface $response) {}

    public function toAsn1(): AbstractType
    {
        return $this->response->toAsn1();
    }
}
