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

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPasswordPolicyForwardHandler;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class ServerPasswordPolicyForwardHandlerTest extends TestCase
{
    private const NOW = '2026-05-20T12:00:00Z';

    private const DN = 'cn=user,dc=foo,dc=bar';

    private WritableLdapBackendInterface&MockObject $backend;

    private ServerPasswordPolicyForwardHandler $subject;

    private ResponseStream $lastStream;

    private AccessControlInterface&MockObject $accessControl;

    protected function setUp(): void
    {
        $this->backend = $this->createMock(WritableLdapBackendInterface::class);
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->subject = new ServerPasswordPolicyForwardHandler(
            $this->backend,
            new PasswordPolicyResolver(
                $this->backend,
                null,
                new PasswordPolicy(lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                )),
            ),
            new PasswordPolicyEngine(
                FrozenClock::fromString(self::NOW),
                new PasswordChangeConstraintChain([]),
            ),
            $this->accessControl,
        );
    }

    public function test_it_unions_forwarded_failures_via_an_atomic_update(): void
    {
        $time = new DateTimeImmutable(
            '2026-05-20 11:59:00',
            new DateTimeZone('UTC'),
        );

        $changes = $this->captureComputedChanges(
            new ForwardPasswordPolicyStateRequest(self::DN, 'uuid', [$time]),
            Entry::fromArray(self::DN, ['cn' => ['user']]),
        );

        self::assertCount(
            1,
            [...$this->lastStream->messages],
        );
        self::assertSame(
            'pwdFailureTime',
            $changes[0]->getAttribute()->getName(),
        );
        self::assertSame(
            ['20260520115900.000000Z'],
            $changes[0]->getAttribute()->getValues(),
        );
    }

    public function test_a_forwarded_success_clears_the_superseded_failures(): void
    {
        $success = new DateTimeImmutable(
            '2026-05-20 12:00:00',
            new DateTimeZone('UTC'),
        );

        $changes = $this->captureComputedChanges(
            new ForwardPasswordPolicyStateRequest(self::DN, 'uuid', [], $success),
            Entry::fromArray(self::DN, [
                'cn' => ['user'],
                'pwdFailureTime' => ['20260520115000Z'],
            ]),
        );

        self::assertSame(
            'pwdFailureTime',
            $changes[0]->getAttribute()->getName(),
        );
        self::assertSame(
            [],
            $changes[0]->getAttribute()->getValues(),
        );
    }

    public function test_it_still_acks_and_does_not_write_when_no_policy_applies(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray(self::DN, ['cn' => ['user']]));
        $this->backend
            ->expects(self::never())
            ->method('atomicUpdate');

        // A resolver with no source at all, so nothing governs the target.
        $subject = new ServerPasswordPolicyForwardHandler(
            $this->backend,
            new PasswordPolicyResolver(
                $this->backend,
                null,
                null,
            ),
            new PasswordPolicyEngine(
                FrozenClock::fromString(self::NOW),
                new PasswordChangeConstraintChain([]),
            ),
            $this->accessControl,
        );

        $stream = $subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(self::DN, 'uuid', [
                new DateTimeImmutable('2026-05-20 11:59:00', new DateTimeZone('UTC')),
            ])),
            $this->createMock(TokenInterface::class),
        );

        self::assertCount(
            1,
            [...$stream->messages],
        );
    }

    public function test_it_still_acks_and_does_not_write_when_the_target_is_missing(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(null);
        $this->backend
            ->expects(self::never())
            ->method('atomicUpdate');

        $stream = $this->subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(self::DN, 'uuid', [
                new DateTimeImmutable('2026-05-20 11:59:00', new DateTimeZone('UTC')),
            ])),
            $this->createMock(TokenInterface::class),
        );

        self::assertCount(
            1,
            [...$stream->messages],
        );
    }

    /**
     * The grant to forward says nothing about which entries, so each attribute is authorized at the target DN.
     */
    public function test_it_authorizes_every_changed_attribute_against_the_target_dn(): void
    {
        $seen = [];
        $this->accessControl
            ->method('authorizeAttribute')
            ->willReturnCallback(function (
                TokenInterface $token,
                Dn $dn,
                string $attribute,
                AttributeAccess $access,
            ) use (&$seen): void {
                $seen[] = $dn->toString() . '/' . $attribute . '/' . $access->name;
            });

        $this->captureComputedChanges(
            new ForwardPasswordPolicyStateRequest(
                self::DN,
                'uuid',
                [new DateTimeImmutable('2026-05-20 11:59:00', new DateTimeZone('UTC'))],
            ),
            Entry::fromArray(self::DN, ['cn' => ['user']]),
        );

        self::assertSame(
            [self::DN . '/pwdFailureTime/Write'],
            $seen,
        );
    }

    public function test_a_denied_attribute_stops_the_forwarded_write(): void
    {
        $this->accessControl
            ->method('authorizeAttribute')
            ->willThrowException(new OperationException(
                'Access denied.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ));

        $compute = null;
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray(self::DN, ['cn' => ['user']]));
        $this->backend
            ->method('atomicUpdate')
            ->with(
                self::anything(),
                self::anything(),
                self::callback(function (callable $fn) use (&$compute): bool {
                    $compute = $fn;

                    return true;
                }),
            );

        $this->subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(
                self::DN,
                'uuid',
                [new DateTimeImmutable('2026-05-20 11:59:00', new DateTimeZone('UTC'))],
            )),
            $this->createMock(TokenInterface::class),
        );

        self::assertNotNull($compute);
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $compute(Entry::fromArray(self::DN, ['cn' => ['user']]));
    }

    public function test_it_rejects_a_request_of_the_wrong_type(): void
    {
        $this->backend
            ->expects(self::never())
            ->method('atomicUpdate');
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->subject->handleRequest(
            $this->messageFor(new ExtendedRequest(ExtendedRequest::OID_PPOLICY_STATE_FORWARD)),
            $this->createMock(TokenInterface::class),
        );
    }

    /**
     * Drive handleRequest, capture the compute closure passed to atomicUpdate, and return its changes for the given
     * entry (or an entry with no applicable policy when $entry is null).
     *
     * @return list<Change>
     */
    private function captureComputedChanges(
        ForwardPasswordPolicyStateRequest $request,
        Entry $entry,
    ): array {
        $captured = [];

        $this->backend
            ->method('get')
            ->willReturn($entry);

        $this->backend
            ->expects(self::once())
            ->method('atomicUpdate')
            ->with(
                self::callback(fn(Dn $dn): bool => $dn->toString() === self::DN),
                self::isInstanceOf(WriteContext::class),
                self::callback(function (callable $compute) use (&$captured, $entry): bool {
                    $result = $compute($entry);

                    foreach (is_array($result) ? $result : [] as $change) {
                        if ($change instanceof Change) {
                            $captured[] = $change;
                        }
                    }

                    return true;
                }),
            );

        $this->lastStream = $this->subject->handleRequest(
            $this->messageFor($request),
            $this->createMock(TokenInterface::class),
        );

        return $captured;
    }

    private function messageFor(ExtendedRequest $request): LdapMessageRequest
    {
        return new LdapMessageRequest(
            1,
            $request,
        );
    }
}
