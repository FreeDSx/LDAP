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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder\Request;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Request\ForwardPasswordPolicyStateRequestDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class ForwardPasswordPolicyStateRequestDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private const UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    private const SUCCESS = '20260102000000Z';

    private const VERSION = '20251201083000.250000Z';

    private ForwardPasswordPolicyStateRequestDecoder $subject;

    private DecodeContext $context;

    private DateTimeImmutable $time;

    private DateTimeImmutable $success;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(ForwardPasswordPolicyStateRequestDecoder::class);
        $this->context = new DecodeContext();
        $this->time = new DateTimeImmutable(
            '2026-01-01 00:00:00',
            new DateTimeZone('UTC'),
        );
        $this->success = new DateTimeImmutable(
            '2026-01-02 00:00:00',
            new DateTimeZone('UTC'),
        );
    }

    public function testItDecodesTheUuidFailureTimesAndLastSuccess(): void
    {
        $request = new ForwardPasswordPolicyStateRequest(
            self::UUID,
            [$this->time],
            $this->success,
        );

        $result = $this->subject->decode(
            self::valueOf($request),
            $this->context,
        );

        self::assertEquals(
            $request->setValue(null),
            $result->setValue(null),
        );
    }

    public function testItDecodesAStateWithoutALastSuccess(): void
    {
        $request = new ForwardPasswordPolicyStateRequest(
            self::UUID,
            [$this->time],
        );

        $result = $this->subject->decode(
            self::valueOf($request),
            $this->context,
        );

        self::assertNull($result->getLastSuccess());
        self::assertEquals(
            $request->setValue(null),
            $result->setValue(null),
        );
    }

    public function testItDecodesAPasswordVersionWithoutALastSuccess(): void
    {
        $request = new ForwardPasswordPolicyStateRequest(
            self::UUID,
            [$this->time],
            null,
            GeneralizedTime::parse('20251201083000.250000Z'),
        );

        $result = $this->subject->decode(
            self::valueOf($request),
            $this->context,
        );

        self::assertNull($result->getLastSuccess());
        self::assertEquals(
            $request->setValue(null),
            $result->setValue(null),
        );
    }

    public function testItDecodesALastSuccessAndAPasswordVersion(): void
    {
        $request = new ForwardPasswordPolicyStateRequest(
            self::UUID,
            [$this->time],
            $this->success,
            GeneralizedTime::parse('20251201083000.250000Z'),
        );

        $result = $this->subject->decode(
            self::valueOf($request),
            $this->context,
        );

        self::assertEquals(
            $request->setValue(null),
            $result->setValue(null),
        );
    }

    public function testItRefusesAMalformedEntryUuid(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The password policy forward request has an invalid entry UUID.');

        $this->subject->decode(
            self::encoded(Asn1::sequence(
                Asn1::octetString('not-a-uuid'),
                Asn1::setOf(),
            )),
            $this->context,
        );
    }

    /**
     * @param AbstractType<mixed> $value
     */
    #[DataProvider('malformedValues')]
    public function testItRefusesAMalformedValue(AbstractType $value): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->decode(
            self::encoded($value),
            $this->context,
        );
    }

    /**
     * @return array<string, array{AbstractType<mixed>}>
     */
    public static function malformedValues(): array
    {
        return [
            'an invalid failure time' => [Asn1::sequence(
                Asn1::octetString(self::UUID),
                Asn1::setOf(Asn1::octetString('not-a-time')),
            )],
            'an invalid last success' => [Asn1::sequence(
                Asn1::octetString(self::UUID),
                Asn1::setOf(),
                Asn1::context(
                    0,
                    Asn1::octetString('not-a-time'),
                ),
            )],
            'an invalid password version' => [Asn1::sequence(
                Asn1::octetString(self::UUID),
                Asn1::setOf(),
                Asn1::context(
                    1,
                    Asn1::octetString('not-a-time'),
                ),
            )],
            'too few components' => [Asn1::sequence(Asn1::octetString(self::UUID))],
            'too many components' => [Asn1::sequence(
                Asn1::octetString(self::UUID),
                Asn1::setOf(),
                Asn1::context(
                    0,
                    Asn1::octetString(self::SUCCESS),
                ),
                Asn1::context(
                    1,
                    Asn1::octetString(self::VERSION),
                ),
                Asn1::octetString('extra'),
            )],
            'an untagged optional component' => [Asn1::sequence(
                Asn1::octetString(self::UUID),
                Asn1::setOf(),
                Asn1::octetString(self::SUCCESS),
            )],
            'a private-tagged optional component' => [Asn1::sequence(
                Asn1::octetString(self::UUID),
                Asn1::setOf(),
                Asn1::private(
                    1,
                    Asn1::octetString(self::VERSION),
                ),
            )],
            'the password version before the last success' => [Asn1::sequence(
                Asn1::octetString(self::UUID),
                Asn1::setOf(),
                Asn1::context(
                    1,
                    Asn1::octetString(self::VERSION),
                ),
                Asn1::context(
                    0,
                    Asn1::octetString(self::SUCCESS),
                ),
            )],
            'a repeated last success' => [Asn1::sequence(
                Asn1::octetString(self::UUID),
                Asn1::setOf(),
                Asn1::context(
                    0,
                    Asn1::octetString(self::SUCCESS),
                ),
                Asn1::context(
                    0,
                    Asn1::octetString(self::SUCCESS),
                ),
            )],
            'an unknown optional tag' => [Asn1::sequence(
                Asn1::octetString(self::UUID),
                Asn1::setOf(),
                Asn1::context(
                    2,
                    Asn1::octetString(self::SUCCESS),
                ),
            )],
            'not a sequence' => [Asn1::set()],
        ];
    }

    private static function valueOf(ExtendedRequest $request): string
    {
        $value = $request->toAsn1()->getChild(1)?->getValue();
        self::assertIsString($value);

        return $value;
    }

    /**
     * @param AbstractType<mixed> $value
     */
    private static function encoded(AbstractType $value): string
    {
        return (new LdapEncoder())->encode($value);
    }
}
