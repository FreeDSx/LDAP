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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessage;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LdapMessageRequestTest extends TestCase
{
    private LdapMessageRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new LdapMessageRequest(
            1,
            new DeleteRequest('dc=foo,dc=bar'),
            new Control('foo'),
        );
    }

    public function test_it_should_get_the_response(): void
    {
        self::assertInstanceOf(
            DeleteRequest::class,
            $this->subject->getRequest(),
        );
    }

    public function test_it_should_get_the_controls(): void
    {
        self::assertTrue($this->subject->controls()->has('foo'));
    }

    public function test_it_should_get_the_message_id(): void
    {
        self::assertSame(
            1,
            $this->subject->getMessageId(),
        );
    }

    public function test_it_should_generate_correct_ASN1(): void
    {
        self::assertEquals(
            Asn1::sequence(
                Asn1::integer(1),
                Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
                Asn1::context(0, Asn1::sequenceOf((new Control('foo'))->toAsn1())),
            ),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_leaves_the_shared_pwd_policy_oid_generic_on_the_request_path(): void
    {
        $encoder = new LdapEncoder();

        $message = LdapMessageRequest::fromAsn1(Asn1::sequence(
            Asn1::integer(2),
            Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
            Asn1::context(0, (new IncompleteType($encoder->encode((new Control(Control::OID_PWD_POLICY))->toAsn1())))->setIsConstructed(true)),
        ));

        self::assertTrue($message->controls()->has(Control::OID_PWD_POLICY));
        self::assertNull($message->controls()->getByClass(PwdPolicyResponseControl::class));
    }

    #[DataProvider('outOfRangeMessageIdProvider')]
    public function test_it_refuses_a_message_id_outside_the_permitted_range(int $messageId): void
    {
        self::expectException(ProtocolException::class);
        self::expectExceptionMessage('The LDAP message ID is outside the range it is permitted to use.');

        LdapMessageRequest::fromAsn1(Asn1::sequence(
            Asn1::integer($messageId),
            Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
        ));
    }

    public static function outOfRangeMessageIdProvider(): Generator
    {
        yield 'negative' => [-1];
        yield 'above maxInt' => [LdapMessage::MAX_INT + 1];
    }

    #[DataProvider('inRangeMessageIdProvider')]
    public function test_it_accepts_a_message_id_at_the_edge_of_the_permitted_range(int $messageId): void
    {
        $message = LdapMessageRequest::fromAsn1(Asn1::sequence(
            Asn1::integer($messageId),
            Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
        ));

        self::assertSame(
            $messageId,
            $message->getMessageId(),
        );
    }

    public static function inRangeMessageIdProvider(): Generator
    {
        // Zero is in range here; it is refused later as reserved rather than as an unparseable ID.
        yield 'zero' => [0];
        yield 'maxInt' => [LdapMessage::MAX_INT];
    }
}
