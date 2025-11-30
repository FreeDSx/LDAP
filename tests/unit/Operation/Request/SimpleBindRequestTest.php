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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use PHPUnit\Framework\TestCase;

final class SimpleBindRequestTest extends TestCase
{
    private SimpleBindRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new SimpleBindRequest(
            '',
            ''
        );
    }

    public function test_it_should_default_to_ldap_v3(): void
    {
        self::assertSame(
            3,
            $this->subject->getVersion(),
        );
    }

    public function test_it_should_set_the_username(): void
    {
        $this->subject->setUsername('bar');

        self::assertSame(
            'bar',
            $this->subject->getUsername(),
        );
    }

    public function test_it_should_set_the_password(): void
    {
        $this->subject->setPassword('bar');

        self::assertSame(
            'bar',
            $this->subject->getPassword(),
        );
    }

    public function test_it_should_allow_non_empty_username_and_password(): void
    {
        $this->subject
            ->setUsername('foo')
            ->setPassword('bar');

        self::assertInstanceOf(
            AbstractType::class,
            $this->subject->toAsn1()
        );
    }

    /**
     * @dataProvider unallowedUsernamePasswordProvider
     */
    public function test_it_should_not_allow_empty_username_and_password_combos(
        string $username,
        string $password,
    ): void {
        $this->expectException(BindException::class);

        $this->subject
            ->setUsername($username)
            ->setPassword($password);

        $this->subject->toAsn1();
    }

    public function test_it_should_correctly_detect_a_zero_string_as_non_empty(): void
    {
        $this->subject->setUsername('foo');
        $this->subject->setPassword('0');

        self::assertInstanceOf(
            AbstractType::class,
            $this->subject->toAsn1()
        );

        $this->subject->setUsername('0');

        self::assertInstanceOf(
            AbstractType::class,
            $this->subject->toAsn1()
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $this->subject
            ->setUsername('foo')
            ->setPassword('bar');

        self::assertEquals(
            Asn1::application(0, Asn1::sequence(
                Asn1::integer(3),
                Asn1::octetString('foo'),
                Asn1::context(0, Asn1::octetString('bar'))
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $bind = new SimpleBindRequest('foo', 'bar');

        self::assertEquals(
            $bind,
            SimpleBindRequest::fromAsn1($bind->toAsn1()),
        );
    }

    /**
     * @dataProvider malformedAsn1DataProvider
     */
    public function test_it_should_detect_invalid_asn1_from_asn1(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);

        SimpleBindRequest::fromAsn1($type);
    }

    /**
     * @return array<array{0: AbstractType}>
     */
    public static function malformedAsn1DataProvider(): array
    {
        return [
            [Asn1::octetString('foo')],
            [Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::integer(3)
            )],
        ];
    }

    /**
     * @return array<array{string, string}>
     */
    public static function unallowedUsernamePasswordProvider(): array
    {
        return [
            ['', ''],
            ['foo', ''],
            ['', 'foo'],
        ];
    }
}
