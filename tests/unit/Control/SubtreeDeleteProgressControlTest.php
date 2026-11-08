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
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\SubtreeDeleteProgressControl;
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
}
