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
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerWhoAmIHandler;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class ServerWhoAmIHandlerTest extends TestCase
{
    private ServerWhoAmIHandler $subject;

    protected function setUp(): void
    {
        $this->subject = new ServerWhoAmIHandler();
    }

    public function test_it_should_handle_a_who_am_i_when_there_is_a_token_with_a_DN_name(): void
    {
        $request = new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI));

        $stream = $this->subject->handleRequest(
            $request,
            BindToken::fromDn(
                'cn=foo,dc=foo,dc=bar',
            ),
        );

        $this->assertEquals(
            [new LdapMessageResponse(
                2,
                new ExtendedResponse(new LdapResult(0), null, 'dn:cn=foo,dc=foo,dc=bar'),
            )],
            [...$stream->messages],
        );
    }

    public function test_it_should_use_resolved_dn_when_it_differs_from_username(): void
    {
        $request = new LdapMessageRequest(
            2,
            new ExtendedRequest(ExtendedRequest::OID_WHOAMI),
        );

        $stream = $this->subject->handleRequest(
            $request,
            BindToken::fromSasl(
                'uid=alice',
                new Dn('cn=Alice,dc=example,dc=com'),
            ),
        );

        $this->assertEquals(
            [new LdapMessageResponse(
                2,
                new ExtendedResponse(
                    new LdapResult(0),
                    null,
                    'dn:cn=Alice,dc=example,dc=com',
                ),
            )],
            [...$stream->messages],
        );
    }

    public function test_it_should_handle_a_who_am_i_when_there_is_a_token_with_a_non_DN_name(): void
    {
        $request = new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI));

        $stream = $this->subject->handleRequest(
            $request,
            BindToken::fromUsername(
                'foo@bar.local',
            ),
        );

        $this->assertEquals(
            [new LdapMessageResponse(
                2,
                new ExtendedResponse(new LdapResult(0), null, 'u:foo@bar.local'),
            )],
            [...$stream->messages],
        );
    }

    public function test_it_should_handle_a_who_am_i_when_there_is_no_token_yet(): void
    {
        $request = new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI));

        $stream = $this->subject->handleRequest(
            $request,
            new AnonToken(),
        );
        $messages = [...$stream->messages];

        $this->assertCount(
            1,
            $messages,
        );
        $response = $messages[0]->getResponse();
        $this->assertInstanceOf(
            ExtendedResponse::class,
            $response,
        );
        $this->assertSame(
            '',
            $response->getValue(),
        );
    }
}
