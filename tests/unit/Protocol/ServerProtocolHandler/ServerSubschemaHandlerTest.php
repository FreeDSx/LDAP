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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSubschemaHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerSubschemaHandlerTest extends TestCase
{
    private ServerQueue&MockObject $mockQueue;

    private TokenInterface&MockObject $mockToken;

    private ServerOptions $options;

    private ServerSubschemaHandler $subject;

    protected function setUp(): void
    {
        $this->options = new ServerOptions();
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockToken = $this->createMock(TokenInterface::class);

        $this->subject = new ServerSubschemaHandler(
            options: $this->options,
            queue: $this->mockQueue,
        );
    }

    private function makeMessage(): LdapMessageRequest
    {
        return new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('cn=Subschema')->useBaseScope(),
        );
    }

    public function test_it_returns_a_stub_subschema_entry(): void
    {
        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::callback(function (LdapMessageResponse $response) {
                    /** @var SearchResultEntry $result */
                    $result = $response->getResponse();
                    $entry = $result->getEntry();

                    return $entry->getDn()->toString() === 'cn=Subschema'
                        && ($entry->get('objectClass')?->has('subschema') ?? false)
                        && ($entry->get('cn')?->has('Subschema') ?? false);
                }),
                self::equalTo(new LdapMessageResponse(1, new SearchResultDone(ResultCode::SUCCESS))),
            );

        $this->subject->handleRequest($this->makeMessage(), $this->mockToken);
    }

    public function test_it_uses_the_configured_subschema_entry_dn(): void
    {
        $this->options->setSubschemaEntry(new Dn('cn=schema,dc=example,dc=com'));

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::callback(function (LdapMessageResponse $response) {
                    /** @var SearchResultEntry $result */
                    $result = $response->getResponse();
                    $entry = $result->getEntry();

                    return $entry->getDn()->toString() === 'cn=schema,dc=example,dc=com'
                        && ($entry->get('cn')?->has('schema') ?? false);
                }),
                self::anything(),
            );

        $this->subject->handleRequest($this->makeMessage(), $this->mockToken);
    }
}
