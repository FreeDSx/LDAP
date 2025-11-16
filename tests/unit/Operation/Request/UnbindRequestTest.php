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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\NullType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use PHPUnit\Framework\TestCase;

final class UnbindRequestTest extends TestCase
{
    public function test_it_should_form_correct_asn1(): void
    {
        $subject = new UnbindRequest();

        self::assertEquals(
            (new NullType())
                ->setTagClass(NullType::TAG_CLASS_APPLICATION)
                ->setTagNumber(2),
            $subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        self::assertEquals(
            new UnbindRequest(),
            UnbindRequest::fromAsn1(Asn1::null()),
        );
    }

    public function test_it_should_not_be_constructed_from_invalid_asn1(): void
    {
        $this->expectException(ProtocolException::class);

        UnbindRequest::fromAsn1(Asn1::octetString('foo'));
    }
}
