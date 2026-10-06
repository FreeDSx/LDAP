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
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Result\EntryResult;
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
