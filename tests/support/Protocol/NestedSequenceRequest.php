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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;

/**
 * Sends a request whose operation is universal sequences nested to a given depth.
 */
final readonly class NestedSequenceRequest implements RequestInterface
{
    public function __construct(private int $depth) {}

    public function toAsn1(): AbstractType
    {
        $type = Asn1::null();
        for ($i = 0; $i < $this->depth; $i++) {
            $type = Asn1::sequence($type);
        }

        return $type;
    }

    public static function fromAsn1(AbstractType $type): never
    {
        throw new ProtocolException('A nested sequence request is only ever sent.');
    }
}
