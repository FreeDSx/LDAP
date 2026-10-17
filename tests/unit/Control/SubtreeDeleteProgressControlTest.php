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

namespace Tests\Unit\FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\SubtreeDeleteProgressControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class SubtreeDeleteProgressControlTest extends TestCase
{
    private LdapEncoder $encoder;

    protected function setUp(): void
    {
        $this->encoder = new LdapEncoder();
    }

    public function test_it_is_not_critical(): void
    {
        self::assertFalse((new SubtreeDeleteProgressControl(25000))->getCriticality());
    }

    public function test_it_generates_the_deleted_count_without_a_remaining_count(): void
    {
        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_SUBTREE_DELETE_PROGRESS),
                Asn1::octetString($this->encoder->encode(Asn1::sequence(Asn1::integer(25000)))),
            ),
            (new SubtreeDeleteProgressControl(25000))->toAsn1(),
        );
    }

    public function test_it_generates_a_remaining_count_when_given_one(): void
    {
        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_SUBTREE_DELETE_PROGRESS),
                Asn1::octetString($this->encoder->encode(Asn1::sequence(
                    Asn1::integer(25000),
                    Asn1::context(
                        0,
                        Asn1::integer(12),
                    ),
                ))),
            ),
            (new SubtreeDeleteProgressControl(
                25000,
                12,
            ))->toAsn1(),
        );
    }

    public function test_it_decodes_the_deleted_count(): void
    {
        $control = SubtreeDeleteProgressControl::fromAsn1(
            $this->decoded(new SubtreeDeleteProgressControl(25000)),
        );

        self::assertSame(
            25000,
            $control->getDeleted(),
        );
        self::assertNull($control->getRemaining());
    }

    public function test_it_decodes_the_remaining_count(): void
    {
        $control = SubtreeDeleteProgressControl::fromAsn1(
            $this->decoded(new SubtreeDeleteProgressControl(
                25000,
                12,
            )),
        );

        self::assertSame(
            12,
            $control->getRemaining(),
        );
    }

    public function test_a_value_without_a_deleted_count_is_refused(): void
    {
        $this->expectException(ProtocolException::class);

        SubtreeDeleteProgressControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_SUBTREE_DELETE_PROGRESS),
            Asn1::octetString($this->encoder->encode(Asn1::sequence(Asn1::octetString('25000')))),
        ));
    }

    /**
     * @return AbstractType<mixed>
     */
    private function decoded(SubtreeDeleteProgressControl $control): AbstractType
    {
        return $this->encoder->decode($this->encoder->encode($control->toAsn1()));
    }
}
