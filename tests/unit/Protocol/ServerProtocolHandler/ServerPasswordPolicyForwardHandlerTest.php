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
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Write\Command\ComputeUpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class ServerPasswordPolicyForwardHandlerTest extends TestCase
{
    private const NOW = '2026-05-20T12:00:00Z';

    private const DN = 'cn=user,dc=foo,dc=bar';

    private const UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    private InMemoryStorage $storage;

    private ReadBackendInterface&MockObject $backend;

    private WriteHandlerInterface&MockObject $writes;

    private ServerPasswordPolicyForwardHandler $subject;

    private ResponseStream $lastStream;

    private AccessControlInterface&MockObject $accessControl;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->backend = $this->createMock(ReadBackendInterface::class);
        $this->writes = $this->createMock(WriteHandlerInterface::class);
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->subject = new ServerPasswordPolicyForwardHandler(
            $this->storage,
            $this->writes,
            $this->resolverWith(new PasswordPolicy(lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: 3,
            ))),
            new PasswordPolicyEngine(
                FrozenClock::fromString(self::NOW),
                new PasswordChangeConstraintChain([]),
            ),
            $this->accessControl,
            FrozenClock::fromString(self::NOW),
        );
    }

    public function test_it_unions_forwarded_failures_via_an_atomic_update(): void
    {
        $time = new DateTimeImmutable(
            '2026-05-20 11:59:00',
            new DateTimeZone('UTC'),
        );
        $target = $this->storeTarget(['cn' => ['user']]);

        $changes = $this->captureComputedChanges(
            new ForwardPasswordPolicyStateRequest(self::UUID, [$time]),
            $target,
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

    public function test_a_forwarded_state_is_written_without_restamping_the_modify_metadata(): void
    {
        $this->storeTarget(['cn' => ['user']]);
        $this->writes
            ->expects(self::once())
            ->method('handle')
            ->with(
                self::isInstanceOf(ComputeUpdateCommand::class),
                self::callback(static fn(WriteContext $context): bool => $context->keepsModifyMetadata()),
            );

        $stream = $this->subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(
                self::UUID,
                [new DateTimeImmutable(
                    '2026-05-20 11:59:00',
                    new DateTimeZone('UTC'),
                )],
            )),
            $this->createMock(TokenInterface::class),
        );

        self::assertCount(
            1,
            [...$stream->messages],
        );
    }

    public function test_a_forwarded_success_clears_the_superseded_failures(): void
    {
        $success = new DateTimeImmutable(
            '2026-05-20 12:00:00',
            new DateTimeZone('UTC'),
        );
        $target = $this->storeTarget([
            'cn' => ['user'],
            'pwdFailureTime' => ['20260520115000Z'],
        ]);

        $changes = $this->captureComputedChanges(
            new ForwardPasswordPolicyStateRequest(self::UUID, [], $success),
            $target,
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
        $this->storeTarget(['cn' => ['user']]);
        $this->writes
            ->expects(self::never())
            ->method('handle');

        // A resolver with no source at all, so nothing governs the target.
        $subject = new ServerPasswordPolicyForwardHandler(
            $this->storage,
            $this->writes,
            $this->resolverWith(null),
            new PasswordPolicyEngine(
                FrozenClock::fromString(self::NOW),
                new PasswordChangeConstraintChain([]),
            ),
            $this->accessControl,
        );

        $stream = $subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(self::UUID, [
                new DateTimeImmutable('2026-05-20 11:59:00', new DateTimeZone('UTC')),
            ])),
            $this->createMock(TokenInterface::class),
        );

        self::assertCount(
            1,
            [...$stream->messages],
        );
    }

    public function test_it_still_acks_and_does_not_write_when_no_entry_holds_the_uuid(): void
    {
        $this->writes
            ->expects(self::never())
            ->method('handle');

        $stream = $this->subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(self::UUID, [
                new DateTimeImmutable('2026-05-20 11:59:00', new DateTimeZone('UTC')),
            ])),
            $this->createMock(TokenInterface::class),
        );

        self::assertCount(
            1,
            [...$stream->messages],
        );
    }

    public function test_it_returns_no_changes_when_the_entry_uuid_no_longer_matches(): void
    {
        $this->storeTarget(['cn' => ['user']]);

        // The entry the write lock re-reads carries a different UUID: the DN was re-occupied since the resolve.
        $changes = $this->captureComputedChanges(
            new ForwardPasswordPolicyStateRequest(self::UUID, [
                new DateTimeImmutable('2026-05-20 11:59:00', new DateTimeZone('UTC')),
            ]),
            Entry::fromArray(self::DN, [
                'cn' => ['user'],
                'entryUUID' => ['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'],
            ]),
        );

        self::assertSame(
            [],
            $changes,
        );
    }

    public function test_a_forward_observed_under_a_password_the_locked_entry_has_replaced_writes_nothing(): void
    {
        $this->storeTarget(['cn' => ['user']]);

        $changes = $this->captureComputedChanges(
            new ForwardPasswordPolicyStateRequest(
                self::UUID,
                [new DateTimeImmutable(
                    '2026-05-20 11:59:00',
                    new DateTimeZone('UTC'),
                )],
                new DateTimeImmutable(
                    '2026-05-20 11:59:30',
                    new DateTimeZone('UTC'),
                ),
                new DateTimeImmutable(
                    '2026-05-19 00:00:00',
                    new DateTimeZone('UTC'),
                ),
            ),
            Entry::fromArray(
                self::DN,
                [
                    'cn' => ['user'],
                    'entryUUID' => [self::UUID],
                    'pwdChangedTime' => ['20260520115945.250000Z'],
                ],
            ),
        );

        self::assertSame(
            [],
            $changes,
        );
        self::assertCount(
            1,
            [...$this->lastStream->messages],
        );
    }

    public function test_a_forward_observed_under_the_password_the_locked_entry_holds_is_applied(): void
    {
        $this->storeTarget(['cn' => ['user']]);

        $changes = $this->captureComputedChanges(
            new ForwardPasswordPolicyStateRequest(
                self::UUID,
                [new DateTimeImmutable(
                    '2026-05-20 11:59:00',
                    new DateTimeZone('UTC'),
                )],
                null,
                GeneralizedTime::parse('20260520115945.250000Z'),
            ),
            Entry::fromArray(
                self::DN,
                [
                    'cn' => ['user'],
                    'entryUUID' => [self::UUID],
                    'pwdChangedTime' => ['20260520115945.250000Z'],
                ],
            ),
        );

        self::assertSame(
            'pwdFailureTime',
            ($changes[0] ?? null)?->getAttribute()->getName(),
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
        $target = $this->storeTarget(['cn' => ['user']]);

        $this->captureComputedChanges(
            new ForwardPasswordPolicyStateRequest(
                self::UUID,
                [new DateTimeImmutable('2026-05-20 11:59:00', new DateTimeZone('UTC'))],
            ),
            $target,
        );

        self::assertSame(
            [
                self::DN . '/pwdFailureTime/Write',
                self::DN . '/pwdFailureTime/Write',
            ],
            $seen,
        );
    }

    public function test_a_denied_attribute_stops_the_forwarded_write(): void
    {
        $this->accessControl
            ->method('authorizeAttribute')
            ->willReturnCallback(static function (
                TokenInterface $token,
                Dn $dn,
                string $attribute,
            ): void {
                if ($attribute === PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME) {
                    throw new OperationException(
                        'Access denied.',
                        ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                    );
                }
            });
        $target = $this->storeTarget(['cn' => ['user']]);

        $compute = null;
        $this->writes
            ->method('handle')
            ->with(self::callback(function (ComputeUpdateCommand $command) use (&$compute): bool {
                $compute = $command->compute;

                return true;
            }));

        $this->subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(
                self::UUID,
                [
                    new DateTimeImmutable(
                        '2026-05-20 11:57:00',
                        new DateTimeZone('UTC'),
                    ),
                    new DateTimeImmutable(
                        '2026-05-20 11:58:00',
                        new DateTimeZone('UTC'),
                    ),
                    new DateTimeImmutable(
                        '2026-05-20 11:59:00',
                        new DateTimeZone('UTC'),
                    ),
                ],
            )),
            $this->createMock(TokenInterface::class),
        );

        self::assertNotNull($compute);
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $compute($target);
    }

    /**
     * @return iterable<string, array{array<string, list<string>>, ?PasswordPolicy}>
     */
    public static function forwardsThatWriteNothing(): iterable
    {
        $policy = new PasswordPolicy(lockout: new PasswordLockoutRules(
            enabled: true,
            maxFailure: 3,
        ));

        yield 'a password the entry has since replaced' => [
            [
                'cn' => ['user'],
                'pwdChangedTime' => ['20260520115945.250000Z'],
            ],
            $policy,
        ];
        yield 'a permanent lock' => [
            [
                'cn' => ['user'],
                'pwdAccountLockedTime' => [PasswordPolicyOid::PERMANENT_LOCK_SENTINEL],
            ],
            $policy,
        ];
        yield 'no governing policy' => [
            ['cn' => ['user']],
            null,
        ];
    }

    /**
     * @param array<string, list<string>> $attributes
     */
    #[DataProvider('forwardsThatWriteNothing')]
    public function test_a_caller_who_may_not_forward_for_the_entry_is_refused_however_the_entry_stands(
        array $attributes,
        ?PasswordPolicy $policy,
    ): void {
        $this->accessControl
            ->method('authorizeAttribute')
            ->willThrowException(new OperationException(
                'Access denied.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ));
        $target = $this->storeTarget($attributes);
        $this->writes
            ->method('handle')
            ->willReturnCallback(static function (ComputeUpdateCommand $command) use ($target): void {
                ($command->compute)($target);
            });
        $subject = new ServerPasswordPolicyForwardHandler(
            $this->storage,
            $this->writes,
            $this->resolverWith($policy),
            new PasswordPolicyEngine(
                FrozenClock::fromString(self::NOW),
                new PasswordChangeConstraintChain([]),
            ),
            $this->accessControl,
            FrozenClock::fromString(self::NOW),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(
                self::UUID,
                [new DateTimeImmutable(
                    '2026-05-20 11:59:00',
                    new DateTimeZone('UTC'),
                )],
            )),
            $this->createMock(TokenInterface::class),
        );
    }

    public function test_it_refuses_a_time_from_the_future(): void
    {
        $this->writes
            ->expects(self::never())
            ->method('handle');
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(self::UUID, [
                new DateTimeImmutable('2026-05-20 13:00:00', new DateTimeZone('UTC')),
            ])),
            $this->createMock(TokenInterface::class),
        );
    }

    public function test_it_rejects_a_request_of_the_wrong_type(): void
    {
        $this->writes
            ->expects(self::never())
            ->method('handle');
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->subject->handleRequest(
            $this->messageFor(new ExtendedRequest(ExtendedRequest::OID_PPOLICY_STATE_FORWARD)),
            $this->createMock(TokenInterface::class),
        );
    }

    private function resolverWith(?PasswordPolicy $policy): PasswordPolicyResolver
    {
        return new PasswordPolicyResolver(
            $this->backend,
            null,
            $policy,
        );
    }

    /**
     * @param array<string, list<string>> $attributes
     */
    private function storeTarget(array $attributes): Entry
    {
        $entry = Entry::fromArray(self::DN, $attributes + ['entryUUID' => [self::UUID]]);
        $this->storage->store($entry);

        return $entry;
    }

    /**
     * Drive handleRequest, capture the compute closure passed to the write command, and return its changes for the
     * given entry.
     *
     * @return list<Change>
     */
    private function captureComputedChanges(
        ForwardPasswordPolicyStateRequest $request,
        Entry $entry,
    ): array {
        $captured = [];

        $this->writes
            ->expects(self::once())
            ->method('handle')
            ->with(
                self::callback(function (ComputeUpdateCommand $command) use (&$captured, $entry): bool {
                    if ($command->dn->toString() !== self::DN) {
                        return false;
                    }

                    foreach (($command->compute)($entry) as $change) {
                        $captured[] = $change;
                    }

                    return true;
                }),
                self::isInstanceOf(WriteContext::class),
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
