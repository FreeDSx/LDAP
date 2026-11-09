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
use FreeDSx\Ldap\Control\Ad\DirSyncResponseControl;
use FreeDSx\Ldap\Control\AssertionControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Control\SubtreeDeleteProgressControl;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class RequestMessageDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private RequestMessageDecoder $subject;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(RequestMessageDecoder::class);
    }

    public function testItDecodesTheRequestAndItsControls(): void
    {
        $message = $this->subject->decode(self::received(new LdapMessageRequest(
            2,
            new DeleteRequest('dc=foo,dc=bar'),
            new PagingControl(
                10,
                'cookie',
            ),
        )));

        $paging = $message->controls()->getByClass(PagingControl::class);

        self::assertSame(
            [2, 'dc=foo,dc=bar', 10, 'cookie'],
            [
                $message->getMessageId(),
                $message->getRequest() instanceof DeleteRequest ? $message->getRequest()->getDn()->toString() : null,
                $paging?->getSize(),
                $paging?->getCookie(),
            ],
        );
    }

    public function testItLeavesThePasswordPolicyControlGenericOnARequest(): void
    {
        $message = $this->subject->decode(self::received(new LdapMessageRequest(
            2,
            new DeleteRequest('dc=foo,dc=bar'),
            new Control(Control::OID_PWD_POLICY),
        )));

        self::assertTrue($message->controls()->has(Control::OID_PWD_POLICY));
        self::assertNull($message->controls()->getByClass(PwdPolicyResponseControl::class));
    }

    #[DataProvider('controlsOnlyAServerSends')]
    public function testItLeavesAControlOnlyAServerSendsGeneric(Control $control): void
    {
        $message = $this->subject->decode(self::received(new LdapMessageRequest(
            2,
            new DeleteRequest('dc=foo,dc=bar'),
            $control,
        )));

        self::assertSame(
            Control::class,
            get_debug_type($message->controls()->get($control->getTypeOid())),
        );
    }

    /**
     * @return iterable<string, array{Control}>
     */
    public static function controlsOnlyAServerSends(): iterable
    {
        yield 'sort response' => [new SortingResponseControl(0)];
        yield 'sort response with a malformed value' => [new Control(
            Control::OID_SORTING_RESPONSE,
            true,
            'garbage',
        )];
        yield 'VLV response' => [new VlvResponseControl(
            1,
            10,
            0,
        )];
        yield 'DirSync response' => [new DirSyncResponseControl(0)];
        yield 'sync state' => [new SyncStateControl(
            SyncStateControl::STATE_ADD,
            str_repeat("\x11", 16),
        )];
        yield 'sync done' => [new SyncDoneControl('cookie')];
        yield 'subtree delete progress' => [new SubtreeDeleteProgressControl(1)];
    }

    public function testAResponseOperationIsRefusedBeforeItIsDecoded(): void
    {
        try {
            $this->subject->decode(Asn1::sequence(
                Asn1::integer(3),
                Asn1::application(
                    5,
                    Asn1::sequence(
                        Asn1::enumerated(0),
                        Asn1::octetString(''),
                        Asn1::octetString(''),
                    ),
                ),
            ));
            self::fail('The response operation should have been refused.');
        } catch (ProtocolException $e) {
            self::assertNotInstanceOf(
                MessageDecodeException::class,
                $e,
            );
            self::assertSame(
                'The tag 5 for the LDAP operation is not supported.',
                $e->getMessage(),
            );
        }
    }

    public function testAnUnrecognizedOperationIsNotAnswerable(): void
    {
        try {
            $this->subject->decode(Asn1::sequence(
                Asn1::integer(3),
                Asn1::application(
                    30,
                    Asn1::octetString('nope'),
                ),
            ));
            self::fail('The unrecognized operation should have been refused.');
        } catch (ProtocolException $e) {
            self::assertNotInstanceOf(
                MessageDecodeException::class,
                $e,
            );
        }
    }

    public function testTheMessageIdIsCheckedBeforeTheOperation(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The LDAP message ID is outside the range it is permitted to use.');

        $this->subject->decode(Asn1::sequence(
            Asn1::integer(-1),
            Asn1::application(
                30,
                Asn1::octetString('nope'),
            ),
        ));
    }

    public function testAFailureInsideTheOperationNamesTheMessageItBelongsTo(): void
    {
        $e = $this->decodeFailureOf(Asn1::sequence(
            Asn1::integer(4),
            Asn1::application(
                8,
                Asn1::sequence(
                    Asn1::octetString('cn=foo,dc=foo,dc=bar'),
                    Asn1::sequenceOf(Asn1::sequence(
                        Asn1::octetString('cn'),
                        Asn1::setOf(),
                    )),
                ),
            ),
        ));

        self::assertSame(
            [4, 8, ResultCode::PROTOCOL_ERROR],
            [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
        );
    }

    public function testAFailureInsideAControlNamesTheMessageItBelongsTo(): void
    {
        $e = $this->decodeFailureOf(self::received(new LdapMessageRequest(
            7,
            new DeleteRequest('dc=foo,dc=bar'),
            new Control(
                Control::OID_PAGING,
                false,
                'not-a-paging-control',
            ),
        )));

        self::assertSame(
            [7, 10, ResultCode::PROTOCOL_ERROR],
            [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
        );
    }

    public function testTheOperationIsDecodedBeforeItsControls(): void
    {
        $e = $this->decodeFailureOf(self::received(new LdapMessageRequest(
            9,
            Operations::search(self::filterNestedPastTheLimit())->base('dc=foo,dc=bar'),
            new AssertionControl(self::filterPastTheItemLimit()),
        )));

        self::assertSame(
            ResultCode::UNWILLING_TO_PERFORM,
            $e->getResultCode(),
        );
    }

    public function testASearchFilterNestedTooDeeplyIsAnsweredAsUnwillingToPerform(): void
    {
        $e = $this->decodeFailureOf(self::received(new LdapMessageRequest(
            5,
            Operations::search(self::filterNestedPastTheLimit())->base('dc=foo,dc=bar'),
        )));

        self::assertSame(
            [5, 3, ResultCode::UNWILLING_TO_PERFORM],
            [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
        );
    }

    public function testAnAssertionFilterNestedTooDeeplyIsAnsweredAsUnwillingToPerform(): void
    {
        $e = $this->decodeFailureOf(self::received(new LdapMessageRequest(
            6,
            new DeleteRequest('dc=foo,dc=bar'),
            new AssertionControl(self::filterNestedPastTheLimit()),
        )));

        self::assertSame(
            [6, 10, ResultCode::UNWILLING_TO_PERFORM],
            [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
        );
    }

    public function testASearchFilterPastTheItemLimitIsAnsweredAsAnAdministrativeLimit(): void
    {
        $e = $this->decodeFailureOf(self::received(new LdapMessageRequest(
            7,
            Operations::search(self::filterPastTheItemLimit())->base('dc=foo,dc=bar'),
        )));

        self::assertSame(
            [7, 3, ResultCode::ADMIN_LIMIT_EXCEEDED],
            [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
        );
    }

    public function testAnAssertionFilterPastTheItemLimitIsAnsweredAsAnAdministrativeLimit(): void
    {
        $e = $this->decodeFailureOf(self::received(new LdapMessageRequest(
            8,
            new DeleteRequest('dc=foo,dc=bar'),
            new AssertionControl(self::filterPastTheItemLimit()),
        )));

        self::assertSame(
            [8, 10, ResultCode::ADMIN_LIMIT_EXCEEDED],
            [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
        );
    }

    public function testAnOperationPastTheElementBudgetIsAnsweredAsAnAdministrativeLimit(): void
    {
        $e = $this->decodeFailureOf(
            self::received(new LdapMessageRequest(
                9,
                Operations::search(Filters::and(
                    Filters::present('cn'),
                    Filters::present('sn'),
                ))->base('dc=foo,dc=bar'),
            )),
            0,
        );

        self::assertSame(
            [9, 3, ResultCode::ADMIN_LIMIT_EXCEEDED],
            [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
        );
    }

    public function testControlsPastTheElementBudgetAreAnsweredAsAnAdministrativeLimit(): void
    {
        $e = $this->decodeFailureOf(
            self::received(new LdapMessageRequest(
                6,
                new DeleteRequest('dc=foo,dc=bar'),
                new Control('1.2.3'),
                new Control('1.2.4'),
                new Control('1.2.5'),
            )),
            5,
        );

        self::assertSame(
            [6, 10, ResultCode::ADMIN_LIMIT_EXCEEDED],
            [$e->getMessageId(), $e->getProtocolOpTag(), $e->getResultCode()],
        );
    }

    /**
     * @param AbstractType<mixed> $pdu
     */
    private function decodeFailureOf(
        AbstractType $pdu,
        ?int $elementBudget = null,
    ): MessageDecodeException {
        try {
            $this->subject->decode(
                $pdu,
                $elementBudget,
            );
        } catch (MessageDecodeException $e) {
            return $e;
        }

        self::fail('The message should have been refused.');
    }

    /**
     * @return AbstractType<mixed>
     */
    private static function received(LdapMessageRequest $message): AbstractType
    {
        $encoder = new LdapEncoder();

        return $encoder->decode($encoder->encode($message->toAsn1()));
    }

    private static function filterNestedPastTheLimit(): FilterInterface
    {
        $filter = Filters::present('cn');
        for ($i = 0; $i <= FilterDecoder::MAX_NESTING_DEPTH; $i++) {
            $filter = Filters::not($filter);
        }

        return $filter;
    }

    private static function filterPastTheItemLimit(): FilterInterface
    {
        return Filters::or(...array_map(
            static fn(int $i): FilterInterface => Filters::present("a{$i}"),
            range(
                0,
                FilterDecoder::MAX_ITEMS,
            ),
        ));
    }
}
