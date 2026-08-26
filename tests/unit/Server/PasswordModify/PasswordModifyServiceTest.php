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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordModify;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyService;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class PasswordModifyServiceTest extends TestCase
{
    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private ReadBackendInterface&MockObject $backend;

    private BindNameResolverInterface&MockObject $resolver;

    private AccessControlInterface&MockObject $accessControl;

    private PasswordPolicyContext $context;

    private Entry $userEntry;

    private BindToken $userToken;

    private PasswordModifyService $subject;

    protected function setUp(): void
    {
        $this->backend = $this->createMock(ReadBackendInterface::class);
        $this->resolver = $this->createMock(BindNameResolverInterface::class);
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $writeHandler = $this->createMock(WriteHandlerInterface::class);
        $this->context = new PasswordPolicyContext();

        $this->userEntry = new Entry(
            new Dn(self::USER_DN),
            new Attribute('userPassword', '12345'),
        );
        $this->userToken = BindToken::fromDn(
            self::USER_DN,
        );

        $this->subject = new PasswordModifyService(
            targetResolver: new PasswordModifyTargetResolver(
                $this->backend,
                $this->resolver,
            ),
            accessControl: $this->accessControl,
            writeDispatcher: $writeHandler,
            hashService: new PasswordHashService(hashCost: 4),
            passwordPolicyContext: $this->context,
        );
    }

    public function test_self_change_returns_the_target_without_a_generated_password(): void
    {
        $this->backend
            ->method('get')
            ->willReturn($this->userEntry);

        $result = $this->subject->change(
            new PasswordModifyRequest(
                null,
                '12345',
                'newpass',
            ),
            $this->userToken,
            new ControlBag(),
        );

        self::assertSame(
            self::USER_DN,
            $result->targetDn->toString(),
        );
        self::assertNull($result->generatedPassword);
    }

    public function test_named_identity_is_resolved_via_the_identity_resolver(): void
    {
        $this->resolver
            ->expects(self::once())
            ->method('resolve')
            ->with(
                self::USER_DN,
                $this->backend,
            )
            ->willReturn($this->userEntry);

        $result = $this->subject->change(
            new PasswordModifyRequest(
                self::USER_DN,
                null,
                'reset123',
            ),
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            new ControlBag(),
        );

        self::assertSame(
            self::USER_DN,
            $result->targetDn->toString(),
        );
    }

    public function test_missing_self_target_throws_no_such_object(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(null);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->change(
            new PasswordModifyRequest(
                null,
                null,
                'newpass',
            ),
            $this->userToken,
            new ControlBag(),
        );
    }

    public function test_unresolvable_named_identity_throws_no_such_object(): void
    {
        $this->resolver
            ->method('resolve')
            ->willReturn(null);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->change(
            new PasswordModifyRequest(
                'cn=ghost,dc=foo,dc=bar',
                null,
                'newpass',
            ),
            $this->userToken,
            new ControlBag(),
        );
    }

    public function test_old_password_may_match_any_stored_value(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(new Entry(
                new Dn(self::USER_DN),
                new Attribute('userPassword', 'first', '12345'),
            ));

        $result = $this->subject->change(
            new PasswordModifyRequest(
                null,
                '12345',
                'newpass',
            ),
            $this->userToken,
            new ControlBag(),
        );

        self::assertSame(
            self::USER_DN,
            $result->targetDn->toString(),
        );
    }

    public function test_wrong_old_password_throws_invalid_credentials(): void
    {
        $this->backend
            ->method('get')
            ->willReturn($this->userEntry);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject->change(
            new PasswordModifyRequest(
                null,
                'wrongpass',
                'newpass',
            ),
            $this->userToken,
            new ControlBag(),
        );
    }

    public function test_access_control_denial_propagates(): void
    {
        $this->backend
            ->method('get')
            ->willReturn($this->userEntry);
        $this->accessControl
            ->method('authorizeOperation')
            ->willThrowException(new OperationException(
                'Access denied.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->change(
            new PasswordModifyRequest(
                null,
                null,
                'newpass',
            ),
            $this->userToken,
            new ControlBag(),
        );
    }

    public function test_absent_new_password_is_server_generated(): void
    {
        $this->backend
            ->method('get')
            ->willReturn($this->userEntry);

        $result = $this->subject->change(
            new PasswordModifyRequest(
                null,
                null,
                null,
            ),
            $this->userToken,
            new ControlBag(),
        );

        self::assertNotNull($result->generatedPassword);
        self::assertSame(
            16,
            strlen($result->generatedPassword),
        );
    }

    public function test_must_change_identity_cannot_target_another_entry(): void
    {
        $this->resolver
            ->method('resolve')
            ->willReturn($this->userEntry);

        $token = BindToken::fromDn(
            'cn=other,dc=foo,dc=bar',
        );
        $token->markMustChangePassword();

        try {
            $this->subject->change(
                new PasswordModifyRequest(
                    self::USER_DN,
                    null,
                    'newpass',
                ),
                $token,
                new ControlBag(),
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNWILLING_TO_PERFORM,
                $e->getCode(),
            );
        }

        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $this->context->getOutcome()?->errorCode,
        );
    }

    public function test_a_missing_target_answers_as_forbidden_when_the_identity_holds_no_rights(): void
    {
        $this->resolver
            ->method('resolve')
            ->willReturn(null);
        $this->accessControl
            ->method('authorizeOperation')
            ->willThrowException(new OperationException(
                'Access denied.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->change(
            new PasswordModifyRequest(
                'cn=ghost,dc=foo,dc=bar',
                null,
                'newpass',
            ),
            $this->userToken,
            new ControlBag(),
        );
    }

    public function test_a_target_that_resolved_to_nothing_is_authorized_against_the_root(): void
    {
        $this->resolver
            ->method('resolve')
            ->willReturn(null);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeOperation')
            ->with(
                OperationType::PasswordModify,
                $this->userToken,
                self::callback(static fn(Dn $dn): bool => $dn->toString() === ''),
            );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->change(
            new PasswordModifyRequest(
                'cn=ghost,dc=foo,dc=bar',
                null,
                'newpass',
            ),
            $this->userToken,
            new ControlBag(),
        );
    }

    public function test_must_change_self_change_clears_the_session_flag(): void
    {
        $this->backend
            ->method('get')
            ->willReturn($this->userEntry);

        $token = BindToken::fromDn(
            self::USER_DN,
        );
        $token->markMustChangePassword();

        $this->subject->change(
            new PasswordModifyRequest(
                null,
                '12345',
                'newpass',
            ),
            $token,
            new ControlBag(),
        );

        self::assertFalse(
            $token->mustChangePassword(),
            'A successful self-change must lift the session must-change restriction.',
        );
    }
}
