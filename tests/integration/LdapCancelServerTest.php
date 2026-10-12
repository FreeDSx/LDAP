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

namespace Tests\Integration\FreeDSx\Ldap;

use FreeDSx\Ldap\Exception\CancelRequestException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Result\EntryResult;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

final class LdapCancelServerTest extends ServerTestCase
{
    use RawClientQueueTrait;

    public function setUp(): void
    {
        parent::setUp();

        $this->createServerProcess(
            'tcp',
            ['--entries=5000'],
        );
        $this->authenticateUser();
    }

    public function testMidStreamCancelStopsSearchAndReturnsSuccess(): void
    {
        $entriesReceived = 0;

        $request = Operations::search(Filters::present('employeeNumber'))
            ->base('dc=foo,dc=bar')
            ->useEntryHandler(function (EntryResult $result) use (&$entriesReceived): void {
                $entriesReceived++;

                if ($entriesReceived >= 100) {
                    throw new CancelRequestException();
                }
            });

        $response = $this->ldapClient()->sendAndReceive($request);

        /** @var SearchResponse $searchResponse */
        $searchResponse = $response->getResponse();

        self::assertInstanceOf(
            SearchResponse::class,
            $searchResponse,
        );
        self::assertSame(
            ResultCode::SUCCESS,
            $searchResponse->getResultCode(),
        );
        self::assertLessThan(
            5000,
            $entriesReceived,
        );
    }

    public function testPostCompletionCancelReturnsNoSuchOperation(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OPERATION);

        $this->ldapClient()->sendAndReceive(Operations::cancel(999));
    }

    #[DataProvider('undecodableCancelValueProvider')]
    public function testACancelWhoseValueCannotBeDecodedIsAnsweredWithoutEndingTheSession(string $value): void
    {
        try {
            $this->ldapClient()->sendAndReceive(new ExtendedRequest(
                ExtendedRequest::OID_CANCEL,
                $value,
            ));
            $this->fail('A cancel value that cannot be decoded should have been refused.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        }

        $this->assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function undecodableCancelValueProvider(): iterable
    {
        yield 'a value that is not BER' => ["\x01\x02\x03"];
        yield 'an empty value' => [''];
    }

    public function testACancelReadWithTheFinalMessageOfASearchIsAnswered(): void
    {
        $queue = $this->rawQueue(timeoutRead: 5);

        try {
            $queue->sendMessage(new LdapMessageRequest(
                1,
                Operations::bind(
                    'cn=user,dc=foo,dc=bar',
                    '12345',
                ),
            ));
            $queue->getMessage(1);

            // 49 entries and the done make 50 messages, so the only check for a signal follows the final one.
            $queue->sendMessage(
                new LdapMessageRequest(
                    2,
                    Operations::search(Filters::equal('objectClass', 'inetOrgPerson'))
                        ->base('dc=foo,dc=bar')
                        ->useSubtreeScope()
                        ->sizeLimit(49),
                ),
                new LdapMessageRequest(
                    3,
                    Operations::cancel(2),
                ),
            );

            self::assertSame(
                [3 => ResultCode::NO_SUCH_OPERATION],
                $this->resultCodesFor(
                    $queue,
                    3,
                ),
            );
        } finally {
            $queue->close();
        }
    }

    public function testACancelNamingItselfCannotBeCanceled(): void
    {
        $queue = $this->rawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            1,
            Operations::bind('cn=user,dc=foo,dc=bar', '12345'),
        ));
        $queue->getMessage(1);
        $queue->sendMessage(new LdapMessageRequest(
            2,
            Operations::cancel(2),
        ));

        $response = $queue->getMessage(2)->getResponse();
        $queue->close();

        self::assertInstanceOf(
            ExtendedResponse::class,
            $response,
        );
        self::assertSame(
            ResultCode::CANNOT_CANCEL,
            $response->getResultCode(),
        );
    }
}
