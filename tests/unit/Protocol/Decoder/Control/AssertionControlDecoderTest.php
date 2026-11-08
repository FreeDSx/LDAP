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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\AssertionControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\AssertionControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class AssertionControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private AssertionControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(AssertionControlDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheFilter(): void
    {
        $control = $this->subject->decode(
            (new AssertionControl(
                Filters::and(
                    Filters::equal(
                        'cn',
                        'foo',
                    ),
                    Filters::present('sn'),
                ),
                false,
            ))->toAsn1(),
            $this->context,
        );

        self::assertSame(
            ['(&(cn=foo)(sn=*))', Control::OID_ASSERTION, false],
            [
                $control->getFilter()->toString(),
                $control->getTypeOid(),
                $control->getCriticality(),
            ],
        );
    }

    public function testItRefusesAValueThatIsNotAFilter(): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->decode(
            self::encodedControl(
                Control::OID_ASSERTION,
                Asn1::octetString('foo'),
            ),
            $this->context,
        );
    }
}
