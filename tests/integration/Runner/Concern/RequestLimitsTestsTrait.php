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

namespace Tests\Integration\FreeDSx\Ldap\Runner\Concern;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Decoder\AttributeSelectionDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\SortingControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\ModifyRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

use function array_fill;
use function array_map;
use function range;

trait RequestLimitsTestsTrait
{
    use RawClientQueueTrait;

    public function testASearchFilterNestedPastTheLimitIsRefusedAsUnwillingToPerformAndTheSessionContinues(): void
    {
        $this->authenticateUser();

        try {
            $this->ldapClient()->search(
                Operations::search(self::filterNestedWithin(FilterDecoder::MAX_NESTING_DEPTH + 1))->base('dc=foo,dc=bar'),
            );
            self::fail('The deeply nested filter should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNWILLING_TO_PERFORM,
                $e->getCode(),
            );
        }

        $entries = $this->ldapClient()->search(
            Operations::search(self::filterNestedWithin(FilterDecoder::MAX_NESTING_DEPTH))->base('dc=foo,dc=bar'),
        );
        self::assertGreaterThan(
            0,
            $entries->count(),
        );
    }

    public function testAnAssertionFilterNestedPastTheLimitIsRefusedAsUnwillingToPerform(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->ldapClient()->compare(
            'cn=user,dc=foo,dc=bar',
            'cn',
            'user',
            Controls::assertion(self::filterNestedWithin(FilterDecoder::MAX_NESTING_DEPTH + 1)),
        );
    }

    public function testASearchFilterPastTheItemLimitIsRefusedAsAnAdministrativeLimitAndTheSessionContinues(): void
    {
        $this->authenticateUser();

        try {
            $this->ldapClient()->search(
                Operations::search(self::filterOfItems(FilterDecoder::MAX_ITEMS + 1))->base('dc=foo,dc=bar'),
            );
            self::fail('The wide filter should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getCode(),
            );
        }

        $entries = $this->ldapClient()->search(
            Operations::search(self::filterOfItems(FilterDecoder::MAX_ITEMS))->base('dc=foo,dc=bar'),
        );
        self::assertGreaterThan(
            0,
            $entries->count(),
        );
    }

    public function testASearchFilterOfEmptySetsPastTheItemLimitIsRefusedAsAnAdministrativeLimit(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->search(
            Operations::search(Filters::or(
                Filters::present('objectClass'),
                ...array_map(
                    static fn(): FilterInterface => Filters::and(),
                    range(
                        1,
                        FilterDecoder::MAX_ITEMS,
                    ),
                ),
            ))->base('dc=foo,dc=bar'),
        );
    }

    public function testASearchFilterPastTheItemLimitIsRefusedBeforeAnyOfItsFiltersIsDecoded(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->search(
            Operations::search(Filters::or(
                self::filterNestedWithin(FilterDecoder::MAX_NESTING_DEPTH + 1),
                ...array_map(
                    static fn(int $i): FilterInterface => Filters::equal(
                        'cn',
                        "absent-{$i}",
                    ),
                    range(
                        1,
                        FilterDecoder::MAX_ITEMS,
                    ),
                ),
            ))->base('dc=foo,dc=bar'),
        );
    }

    public function testAnAssertionFilterPastTheItemLimitIsRefusedAsAnAdministrativeLimit(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->compare(
            'cn=user,dc=foo,dc=bar',
            'cn',
            'user',
            Controls::assertion(self::filterOfItems(FilterDecoder::MAX_ITEMS + 1)),
        );
    }

    public function testASearchSelectingAsManyAttributesAsTheLimitAllowsIsAnswered(): void
    {
        $queue = $this->boundRawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            2,
            self::searchSelecting(AttributeSelectionDecoder::MAX_ATTRIBUTES),
        ));

        try {
            self::assertSame(
                [2 => ResultCode::SUCCESS],
                $this->resultCodesFor(
                    $queue,
                    2,
                ),
            );
        } finally {
            $queue->close();
        }
    }

    public function testASearchSelectingMoreAttributesThanTheLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(
            self::searchSelecting(AttributeSelectionDecoder::MAX_ATTRIBUTES + 1),
        );
    }

    public function testASortControlPastTheKeyLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(
            self::baseSearch(),
            Controls::sort(...array_fill(
                0,
                SortingControlDecoder::MAX_KEYS + 1,
                new SortKey('cn'),
            )),
        );
    }

    public function testARequestCarryingMoreControlsThanTheLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(
            self::baseSearch(),
            ...array_fill(
                0,
                RequestMessageDecoder::MAX_CONTROLS + 1,
                new Control('1.2.3.4'),
            ),
        );
    }

    public function testAPostReadControlSelectingMoreAttributesThanTheLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(
            Operations::modify(
                'cn=user,dc=foo,dc=bar',
                Change::replace(
                    'description',
                    'x',
                ),
            ),
            Controls::postRead(...self::attributeNames(AttributeSelectionDecoder::MAX_ATTRIBUTES + 1)),
        );
    }

    public function testAControlsListPastTheElementLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(
            self::baseSearch(),
            ...array_fill(
                0,
                60_000,
                new Control('1.2.3.4'),
            ),
        );
    }

    public function testAPasswordModifyValuePastTheElementLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(new ExtendedRequest(
            ExtendedRequest::OID_PWD_MODIFY,
            (new LdapEncoder())->encode(Asn1::sequence(...array_fill(
                0,
                120_000,
                Asn1::context(
                    2,
                    Asn1::octetString('x'),
                ),
            ))),
        ));
    }

    public function testAModifyPastTheChangeLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(Operations::modify(
            'cn=user,dc=foo,dc=bar',
            ...array_fill(
                0,
                ModifyRequestDecoder::MAX_CHANGES + 1,
                Change::replace(
                    'description',
                    'x',
                ),
            ),
        ));
    }

    public function testABindPastTheElementLimitLeavesTheSessionAnonymous(): void
    {
        $client = $this->buildClient('tcp');
        $client->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        try {
            $client->sendAndReceive(
                Operations::bind(
                    'cn=user,dc=foo,dc=bar',
                    '12345',
                ),
                ...array_fill(
                    0,
                    60_000,
                    new Control('1.2.3.4'),
                ),
            );
            self::fail('The bind was accepted past the element limit.');
        } catch (BindException $e) {
            self::assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getCode(),
            );
        }

        self::assertSame(
            '',
            $client->whoami(),
        );
    }

    public function testASaslContinuationPastTheElementLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--sasl'],
        );
        $queue = $this->rawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                1,
                new SaslBindRequest('CRAM-MD5'),
            ));
            self::assertSame(
                [1 => ResultCode::SASL_BIND_IN_PROGRESS],
                $this->resultCodesFor(
                    $queue,
                    1,
                ),
            );

            $queue->sendMessage(new LdapMessageRequest(
                2,
                new SaslBindRequest(
                    'CRAM-MD5',
                    'cn=user,dc=foo,dc=bar 00000000000000000000000000000000',
                ),
                ...self::controlsPastTheElementLimitWithinTheAnonymousSize(),
            ));
            self::assertSame(
                [2 => ResultCode::ADMIN_LIMIT_EXCEEDED],
                $this->resultCodesFor(
                    $queue,
                    2,
                ),
            );

            $queue->sendMessage(new LdapMessageRequest(
                3,
                Operations::read(''),
            ));
            self::assertSame(
                [3 => ResultCode::SUCCESS],
                $this->resultCodesFor(
                    $queue,
                    3,
                ),
            );
        } finally {
            $queue->close();
        }
    }

    private function assertAnsweredAsAnAdministrativeLimit(
        RequestInterface $request,
        Control ...$controls,
    ): void {
        $queue = $this->boundRawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                2,
                $request,
                ...$controls,
            ));
            self::assertSame(
                [2 => ResultCode::ADMIN_LIMIT_EXCEEDED],
                $this->resultCodesFor(
                    $queue,
                    2,
                ),
            );

            $queue->sendMessage(new LdapMessageRequest(
                3,
                self::baseSearch(),
            ));
            self::assertSame(
                [3 => ResultCode::SUCCESS],
                $this->resultCodesFor(
                    $queue,
                    3,
                ),
            );
        } finally {
            $queue->close();
        }
    }

    private static function baseSearch(): SearchRequest
    {
        return Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useBaseScope();
    }

    private static function searchSelecting(int $attributes): SearchRequest
    {
        return Operations::search(
            Filters::present('objectClass'),
            ...self::attributeNames($attributes),
        )
            ->base('dc=foo,dc=bar')
            ->useBaseScope();
    }

    /**
     * @return list<string>
     */
    private static function attributeNames(int $count): array
    {
        return array_map(
            static fn(int $i): string => "attr{$i}",
            range(
                1,
                $count,
            ),
        );
    }

    /**
     * Controls past the element limit that stay within the size a session without a bind may send.
     *
     * @return list<Control>
     */
    private static function controlsPastTheElementLimitWithinTheAnonymousSize(): array
    {
        return array_fill(
            0,
            55_000,
            new Control(''),
        );
    }

    private static function filterNestedWithin(int $depth): FilterInterface
    {
        $filter = Filters::present('objectClass');
        for ($i = 0; $i < $depth; $i++) {
            $filter = Filters::not($filter);
        }

        return $filter;
    }

    /**
     * An OR whose first item matches every entry and whose others name values no entry holds.
     */
    private static function filterOfItems(int $count): FilterInterface
    {
        return Filters::or(
            Filters::present('objectClass'),
            ...array_map(
                static fn(int $i): FilterInterface => Filters::equal(
                    'cn',
                    "absent-{$i}",
                ),
                range(
                    2,
                    $count,
                ),
            ),
        );
    }
}
