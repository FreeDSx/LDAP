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
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\SubentriesControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\SubentriesControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\Protocol\TrailingComponentTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SubentriesControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;
    use TrailingComponentTrait;

    private SubentriesControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SubentriesControlDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesTheVisibility(): void
    {
        $control = $this->subject->decode(
            self::encodedControl(
                Control::OID_SUBENTRIES,
                Asn1::boolean(true),
                true,
            ),
            $this->context,
        );

        self::assertSame(
            [true, true, Control::OID_SUBENTRIES],
            [
                $control->getIsVisible(),
                $control->getCriticality(),
                $control->getTypeOid(),
            ],
        );
    }

    public function testItIgnoresATrailingComponentItDoesNotRecognize(): void
    {
        self::assertFalse($this->subject->decode(
            self::withTrailingComponent((new SubentriesControl(false))->toAsn1()),
            $this->context,
        )->getIsVisible());
    }

    public function testItRefusesAValueThatIsNotABoolean(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('Expected a boolean type for a subentries control value.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_SUBENTRIES,
                Asn1::integer(1),
            ),
            $this->context,
        );
    }
}
