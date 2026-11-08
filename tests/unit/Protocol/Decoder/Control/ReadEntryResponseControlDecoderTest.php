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
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\ReadEntryResponseControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Response\SearchResultEntryDecoder;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class ReadEntryResponseControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private ReadEntryResponseControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = new ReadEntryResponseControlDecoder(
            PostReadResponseControl::class,
            $this->fromContainer(SearchResultEntryDecoder::class),
        );
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheEntry(): void
    {
        $control = $this->subject->decode(
            (new PostReadResponseControl(Entry::fromArray(
                'cn=foo,dc=ex,dc=com',
                [
                    'cn' => ['foo'],
                    'sn' => ['bar', 'baz'],
                ],
            )))->toAsn1(),
            $this->context,
        );

        self::assertSame(
            ['cn=foo,dc=ex,dc=com', ['foo'], ['bar', 'baz'], Control::OID_POST_READ],
            [
                $control->getEntry()->getDn()->toString(),
                $control->getEntry()->get('cn')?->getValues(),
                $control->getEntry()->get('sn')?->getValues(),
                $control->getTypeOid(),
            ],
        );
    }

    public function testItBuildsTheControlClassItIsGiven(): void
    {
        self::assertInstanceOf(
            PreReadResponseControl::class,
            (new ReadEntryResponseControlDecoder(
                PreReadResponseControl::class,
                $this->fromContainer(SearchResultEntryDecoder::class),
            ))->decode(
                (new PreReadResponseControl(Entry::fromArray('cn=foo,dc=ex,dc=com')))->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItRefusesAValueThatIsNotAnEntry(): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->decode(
            self::encodedControl(
                Control::OID_POST_READ,
                Asn1::sequence(Asn1::integer(1)),
            ),
            $this->context,
        );
    }
}
