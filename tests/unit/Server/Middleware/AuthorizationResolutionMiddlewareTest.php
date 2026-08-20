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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Middleware\AuthorizationResolutionMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;

final class AuthorizationResolutionMiddlewareTest extends TestCase
{
    private ServerAuthorization $authorization;

    private PasswordPolicyContext $passwordPolicyContext;

    private RecordingMiddlewareHandler $next;

    protected function setUp(): void
    {
        $this->authorization = new ServerAuthorization(new ServerOptions());
        $this->passwordPolicyContext = new PasswordPolicyContext();
        $this->next = new RecordingMiddlewareHandler(new CallLog());
    }

    public function test_a_request_requiring_authentication_is_rejected(): void
    {
        try {
            $this->subject()->process(
                $this->context(),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertNull($this->next->received);
    }

    public function test_a_request_requiring_a_password_change_is_rejected_and_stashes_the_control(): void
    {
        $token = BindToken::fromDn('cn=user,dc=foo,dc=bar');
        $token->markMustChangePassword();
        $this->authorization->setToken($token);

        try {
            $this->subject()->process(
                $this->context(),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $this->passwordPolicyContext->getOutcome()?->errorCode,
        );
        self::assertNull($this->next->received);
    }

    public function test_an_authorized_request_is_delegated_with_the_resolved_token(): void
    {
        $token = BindToken::fromDn('cn=user,dc=foo,dc=bar');
        $this->authorization->setToken($token);

        $this->subject()->process(
            $this->context(),
            $this->next,
        );

        self::assertNotNull($this->next->received);
        self::assertSame(
            $token,
            $this->next->received->tokenOrFail(),
        );
    }

    private function subject(): AuthorizationResolutionMiddleware
    {
        return new AuthorizationResolutionMiddleware(
            new DispatchAuthorizer($this->authorization),
            $this->passwordPolicyContext,
        );
    }

    private function context(): ServerRequestContext
    {
        return new ServerRequestContext(new LdapMessageRequest(
            1,
            new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true),
        ));
    }
}
