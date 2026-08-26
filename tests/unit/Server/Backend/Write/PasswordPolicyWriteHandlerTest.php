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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\StorageReadBackend;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\PasswordPolicyWriteHandler;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriter;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\HistoryEntry;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class PasswordPolicyWriteHandlerTest extends TestCase
{
    use ServerContainerTrait;

    private const NOW = '2026-05-20T12:00:00Z';

    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private FrozenClock $clock;

    private StorageReadBackend $backend;

    private PasswordPolicyContext $context;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString(self::NOW);
        $this->context = new PasswordPolicyContext();
    }

    public function test_a_modification_not_touching_user_password_passes_straight_through(): void
    {
        $handler = $this->handler(new PasswordPolicy());

        $handler->handle(
            new UpdateCommand(
                new Dn(self::USER_DN),
                [Change::replace('description', 'hello')],
            ),
            $this->writeContext(),
        );

        $entry = $this->backend->get(new Dn(self::USER_DN));
        self::assertNotNull($entry);
        self::assertSame(
            'hello',
            $entry->get('description')?->firstValue(),
        );
        self::assertNull($entry->get(PasswordPolicyOid::NAME_PWD_CHANGED_TIME));
    }

    public function test_a_command_that_sets_no_password_passes_straight_through(): void
    {
        $handler = $this->handler(new PasswordPolicy());

        $handler->handle(
            new DeleteCommand(new Dn(self::USER_DN)),
            $this->writeContext(),
        );

        self::assertNull($this->backend->get(new Dn(self::USER_DN)));
    }

    public function test_allowed_change_writes_password_and_bookkeeping(): void
    {
        $handler = $this->handler(new PasswordPolicy(
            quality: new PasswordQualityRules(inHistory: 3),
        ));

        $handler->handle(
            new UpdateCommand(
                new Dn(self::USER_DN),
                [Change::replace('userPassword', 'a-fresh-password')],
            ),
            $this->writeContext(),
        );

        $entry = $this->backend->get(new Dn(self::USER_DN));
        self::assertNotNull($entry);
        self::assertSame(
            'a-fresh-password',
            $entry->get('userPassword')?->firstValue(),
        );
        self::assertNotNull($entry->get(PasswordPolicyOid::NAME_PWD_CHANGED_TIME));
        self::assertNotNull($entry->get(PasswordPolicyOid::NAME_PWD_HISTORY));
    }

    public function test_reused_password_is_rejected_and_password_left_unchanged(): void
    {
        $handler = $this->handler(
            new PasswordPolicy(quality: new PasswordQualityRules(inHistory: 5)),
            [PasswordPolicyOid::NAME_PWD_HISTORY => $this->historyValue('previous-pass')],
        );

        try {
            $handler->handle(
                new UpdateCommand(
                    new Dn(self::USER_DN),
                    [Change::replace('userPassword', 'previous-pass')],
                ),
                $this->writeContext(),
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }

        self::assertSame(
            PwdPolicyError::PASSWORD_IN_HISTORY,
            $this->context->getOutcome()?->errorCode,
        );
        self::assertSame(
            'original-pass',
            $this->backend->get(new Dn(self::USER_DN))?->get('userPassword')?->firstValue(),
            'A rejected change must not modify the stored password.',
        );
    }

    public function test_a_weak_value_tacked_on_after_a_valid_one_is_rejected(): void
    {
        $handler = $this->handler(new PasswordPolicy(
            quality: new PasswordQualityRules(minLength: 8),
        ));

        try {
            $handler->handle(
                new UpdateCommand(
                    new Dn(self::USER_DN),
                    [Change::replace('userPassword', 'a-strong-password', 'weak')],
                ),
                $this->writeContext(),
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }

        self::assertSame(
            PwdPolicyError::PASSWORD_TOO_SHORT,
            $this->context->getOutcome()?->errorCode,
        );
        self::assertSame(
            'original-pass',
            $this->backend->get(new Dn(self::USER_DN))?->get('userPassword')?->firstValue(),
            'A rejected multi-value set must leave the stored password untouched.',
        );
    }

    /**
     * draft-behera-11 §8.2.7 retains the password being replaced, so a multi-valued set records what it superseded.
     */
    public function test_multi_value_set_records_the_replaced_values_in_history(): void
    {
        $handler = $this->handler(new PasswordPolicy(
            quality: new PasswordQualityRules(inHistory: 5),
        ));

        $handler->handle(
            new UpdateCommand(
                new Dn(self::USER_DN),
                [Change::replace('userPassword', 'first-new-pass', 'second-new-pass')],
            ),
            $this->writeContext(),
        );

        $entry = $this->backend->get(new Dn(self::USER_DN));
        self::assertNotNull($entry);
        $stored = array_map(
            static fn(string $value): string => HistoryEntry::decode($value)->data,
            $entry->get(PasswordPolicyOid::NAME_PWD_HISTORY)?->getValues() ?? [],
        );
        self::assertSame(
            ['original-pass'],
            $stored,
        );
    }

    /**
     * The new values are not in history, so §8.2.6's current-password clause is what stops either being reused.
     */
    public function test_a_value_just_set_cannot_be_set_again(): void
    {
        $handler = $this->handler(new PasswordPolicy(
            quality: new PasswordQualityRules(inHistory: 5),
        ));
        $handler->handle(
            new UpdateCommand(
                new Dn(self::USER_DN),
                [Change::replace('userPassword', 'first-new-pass')],
            ),
            $this->writeContext(),
        );

        $this->expectException(OperationException::class);
        $handler->handle(
            new UpdateCommand(
                new Dn(self::USER_DN),
                [Change::replace('userPassword', 'first-new-pass')],
            ),
            $this->writeContext(),
        );
    }

    public function test_safe_modify_is_satisfied_by_delete_old_add_new(): void
    {
        $handler = $this->handler(new PasswordPolicy(
            change: new PasswordChangeRules(safeModify: true),
        ));

        $handler->handle(
            new UpdateCommand(
                new Dn(self::USER_DN),
                [
                    Change::delete('userPassword', 'original-pass'),
                    Change::add('userPassword', 'a-fresh-password'),
                ],
            ),
            $this->writeContext(),
        );

        self::assertContains(
            'a-fresh-password',
            $this->backend->get(new Dn(self::USER_DN))?->get('userPassword')?->getValues() ?? [],
        );
    }

    public function test_safe_modify_rejects_a_replace_without_the_old_password(): void
    {
        $handler = $this->handler(new PasswordPolicy(
            change: new PasswordChangeRules(safeModify: true),
        ));

        try {
            $handler->handle(
                new UpdateCommand(
                    new Dn(self::USER_DN),
                    [Change::replace('userPassword', 'a-fresh-password')],
                ),
                $this->writeContext(),
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertSame(
            PwdPolicyError::MUST_SUPPLY_OLD_PASSWORD,
            $this->context->getOutcome()?->errorCode,
        );
    }

    public function test_without_a_policy_it_writes_without_bookkeeping(): void
    {
        $handler = $this->handler(null);

        $handler->handle(
            new UpdateCommand(
                new Dn(self::USER_DN),
                [Change::replace('userPassword', 'a-fresh-password')],
            ),
            $this->writeContext(),
        );

        $entry = $this->backend->get(new Dn(self::USER_DN));
        self::assertNotNull($entry);
        self::assertSame(
            'a-fresh-password',
            $entry->get('userPassword')?->firstValue(),
        );
        self::assertNull($entry->get(PasswordPolicyOid::NAME_PWD_CHANGED_TIME));
    }

    public function test_an_add_stamps_its_bookkeeping_under_an_enforcing_schema(): void
    {
        $handler = $this->handler(
            policy: new PasswordPolicy(quality: new PasswordQualityRules(inHistory: 3)),
            options: TestServerOptions::defaults(),
        );
        $dn = new Dn('cn=new,dc=foo,dc=bar');

        $handler->handle(
            new AddCommand(Entry::fromArray(
                $dn->toString(),
                [
                    'objectClass' => ['inetOrgPerson'],
                    'cn' => ['new'],
                    'sn' => ['New'],
                    'userPassword' => ['a-fresh-password'],
                ],
            )),
            $this->writeContext(),
        );

        $entry = $this->backend->get($dn);
        self::assertNotNull($entry);
        self::assertNotNull($entry->get(PasswordPolicyOid::NAME_PWD_CHANGED_TIME));
    }

    /**
     * @param array<string, string> $userAttrs
     */
    private function handler(
        ?PasswordPolicy $policy,
        array $userAttrs = [],
        ?ServerOptions $options = null,
    ): PasswordPolicyWriteHandler {
        $options ??= TestServerOptions::cheaplyHashed();
        $container = $this->containerFor(new InMemoryStorage([
            Entry::fromArray(
                'dc=foo,dc=bar',
                [
                    'objectClass' => ['domain'],
                    'dc' => ['foo'],
                ],
            ),
            Entry::fromArray(
                self::USER_DN,
                [
                    'objectClass' => ['inetOrgPerson'],
                    'cn' => ['user'],
                    'sn' => ['User'],
                    'userPassword' => ['original-pass'],
                ] + $userAttrs,
            ),
        ]), $options);
        $this->backend = $container->get(StorageReadBackend::class);
        $writes = $container->get(WriteOperationDispatcher::class);

        $guard = new PasswordPolicyChangeGuard(
            $this->fromContainer(
                PasswordPolicyEngine::class,
                [ClockInterface::class => $this->clock],
                $options,
            ),
            new PasswordPolicyResolver(
                $this->backend,
                null,
                $policy,
            ),
            $this->context,
            new EventLogger(null, EventLogPolicy::all()),
        );

        return new PasswordPolicyWriteHandler(
            $this->backend,
            $writes,
            $guard,
            new SystemChangeWriter($writes),
        );
    }

    private function writeContext(): WriteContext
    {
        return new WriteContext(
            BindToken::fromDn(
                self::USER_DN,
            ),
            new ControlBag(),
        );
    }

    private function historyValue(string $plaintext): string
    {
        return HistoryEntry::forStoredPassword(
            $this->clock->now(),
            '{BCRYPT}' . password_hash($plaintext, PASSWORD_BCRYPT, ['cost' => 4]),
        )->encode();
    }
}
