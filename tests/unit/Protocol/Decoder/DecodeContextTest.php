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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class DecodeContextTest extends TestCase
{
    private DecodeContext $subject;

    protected function setUp(): void
    {
        $this->subject = new DecodeContext(new LdapEncoder());
    }

    public function testItCompletesAnIncompleteTypeAsTheTypeItIsTold(): void
    {
        $encoded = (new LdapEncoder())->encode(Asn1::sequence(
            Asn1::octetString('cn'),
            Asn1::octetString('foo'),
        ));
        $incomplete = (new IncompleteType(substr(
            $encoded,
            2,
        )))->setIsConstructed(true);

        self::assertEquals(
            [
                Asn1::octetString('cn'),
                Asn1::octetString('foo'),
            ],
            $this->subject->complete(
                $incomplete,
                AbstractType::TAG_TYPE_SEQUENCE,
            )->getChildren(),
        );
    }

    public function testItDecodesEncodedBytes(): void
    {
        self::assertEquals(
            Asn1::sequence(
                Asn1::integer(5),
                Asn1::boolean(true),
            ),
            $this->subject->decode((new LdapEncoder())->encode(Asn1::sequence(
                Asn1::integer(5),
                Asn1::boolean(true),
            ))),
        );
    }
}
