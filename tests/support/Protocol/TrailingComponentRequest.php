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

/**
 * Sends a request carrying a trailing component that a later protocol extension might add.
 */
final readonly class TrailingComponentRequest implements RequestInterface
{
    use TrailingComponentTrait;

    public function __construct(private RequestInterface $request) {}

    public function toAsn1(): AbstractType
    {
        return self::withTrailingComponent($this->request->toAsn1());
    }
}
