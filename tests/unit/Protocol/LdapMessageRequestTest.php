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
use FreeDSx\Ldap\Control\AssertionControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Factory\FilterFactory;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessage;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
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

    public function test_a_failure_inside_the_operation_names_the_message_it_belongs_to(): void
    {
        try {
            LdapMessageRequest::fromAsn1(self::addRequestWithNoValues());
            self::fail('The valueless attribute should have been refused.');
        } catch (MessageDecodeException $e) {
            self::assertSame(
                4,
                $e->getMessageId(),
            );
            self::assertSame(
                8,
                $e->getProtocolOpTag(),
            );
        }
    }

    public function test_a_failure_inside_a_control_names_the_message_it_belongs_to(): void
    {
        $encoder = new LdapEncoder();

        try {
            LdapMessageRequest::fromAsn1(Asn1::sequence(
                Asn1::integer(7),
                Asn1::application(10, Asn1::octetString('dc=foo,dc=bar')),
                Asn1::context(0, (new IncompleteType($encoder->encode(
                    (new Control(Control::OID_PAGING, false, 'not-a-paging-control'))->toAsn1(),
                )))->setIsConstructed(true)),
            ));
            self::fail('The malformed control value should have been refused.');
        } catch (MessageDecodeException $e) {
            self::assertSame(
                7,
                $e->getMessageId(),
            );
            self::assertSame(
                10,
                $e->getProtocolOpTag(),
            );
        }
    }

    public function test_a_search_filter_nested_too_deeply_is_answered_as_unwilling_to_perform(): void
    {
        try {
            self::decodeReceived(new LdapMessageRequest(
                5,
                Operations::search(self::filterNestedPastTheLimit())->base('dc=foo,dc=bar'),
            ));
            self::fail('The deeply nested filter should have been refused.');
        } catch (MessageDecodeException $e) {
            self::assertSame(
                [5, 3, ResultCode::UNWILLING_TO_PERFORM],
                [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
            );
        }
    }

    public function test_an_assertion_filter_nested_too_deeply_is_answered_as_unwilling_to_perform(): void
    {
        try {
            self::decodeReceived(new LdapMessageRequest(
                6,
                new DeleteRequest('dc=foo,dc=bar'),
                new AssertionControl(self::filterNestedPastTheLimit()),
            ));
            self::fail('The deeply nested assertion filter should have been refused.');
        } catch (MessageDecodeException $e) {
            self::assertSame(
                [6, 10, ResultCode::UNWILLING_TO_PERFORM],
                [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
            );
        }
    }

    /**
     * An unrecognized operation cannot be answered, so it must stay a plain failure that ends the session.
     */
    public function test_an_unrecognized_operation_is_not_answerable(): void
    {
        try {
            LdapMessageRequest::fromAsn1(Asn1::sequence(
                Asn1::integer(3),
                Asn1::application(30, Asn1::octetString('nope')),
            ));
            self::fail('The unrecognized operation should have been refused.');
        } catch (ProtocolException $e) {
            self::assertNotInstanceOf(
                MessageDecodeException::class,
                $e,
            );
        }
    }

    /**
     * @return SequenceType<mixed>
     */
    private static function addRequestWithNoValues(): SequenceType
    {
        return Asn1::sequence(
            Asn1::integer(4),
            Asn1::application(8, Asn1::sequence(
                Asn1::octetString('cn=foo,dc=foo,dc=bar'),
                Asn1::sequenceOf(Asn1::sequence(
                    Asn1::octetString('cn'),
                    Asn1::setOf(),
                )),
            )),
        );
    }

    private static function filterNestedPastTheLimit(): FilterInterface
    {
        $filter = Filters::present('cn');
        for ($i = 0; $i <= FilterFactory::MAX_NESTING_DEPTH; $i++) {
            $filter = Filters::not($filter);
        }

        return $filter;
    }

    private static function decodeReceived(LdapMessageRequest $message): LdapMessageRequest
    {
        $encoder = new LdapEncoder();

        return LdapMessageRequest::fromAsn1($encoder->decode($encoder->encode($message->toAsn1())));
    }
}
