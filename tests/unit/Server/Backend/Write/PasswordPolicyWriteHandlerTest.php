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
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\PasswordPolicyWriteHandler;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriter;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\AllowUserChangeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\HistoryConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\MinAgeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\QualityConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\SafeModifyConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\HistoryEntry;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\DefaultPasswordQualityChecker;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Storage\BackendFactoryTrait;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class PasswordPolicyWriteHandlerTest extends TestCase
{
    use BackendFactoryTrait;

    private const NOW = '2026-05-20T12:00:00Z';

    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private FrozenClock $clock;

    private WritableStorageBackend $backend;

    private PasswordPolicyContext $context;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString(self::NOW);
        $this->context = new PasswordPolicyContext();
    }

    public function test_supports_a_user_password_replace(): void
    {
        $handler = $this->handler(new PasswordPolicy());

        self::assertTrue($handler->supports(new UpdateCommand(
            new Dn(self::USER_DN),
            [Change::replace('userPassword', 'newpass')],
        )));
    }

    public function test_ignores_modifications_that_do_not_touch_user_password(): void
    {
        $handler = $this->handler(new PasswordPolicy());

        self::assertFalse($handler->supports(new UpdateCommand(
            new Dn(self::USER_DN),
            [Change::replace('description', 'hello')],
        )));
    }

    public function test_ignores_non_update_commands(): void
    {
        $handler = $this->handler(new PasswordPolicy());

        self::assertFalse($handler->supports(new DeleteCommand(new Dn(self::USER_DN))));
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

    public function test_multi_value_set_records_each_new_value_in_history(): void
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
        // Both new values must be retained so neither can be reused after a multi-valued set.
        self::assertContains(
            'first-new-pass',
            $stored,
        );
        self::assertContains(
            'second-new-pass',
            $stored,
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
                ResultCode::CONSTRAINT_VIOLATION,
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

    /**
     * @param array<string, string> $userAttrs
     */
    private function handler(
        ?PasswordPolicy $policy,
        array $userAttrs = [],
    ): PasswordPolicyWriteHandler {
        $this->backend = self::makeWritableBackend(new InMemoryStorage([
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
        ]));

        $guard = new PasswordPolicyChangeGuard(
            new PasswordPolicyEngine(
                clock: $this->clock,
                changeConstraints: new PasswordChangeConstraintChain([
                    new AllowUserChangeConstraint(),
                    new SafeModifyConstraint(),
                    new MinAgeConstraint($this->clock),
                    new QualityConstraint(new DefaultPasswordQualityChecker()),
                    new HistoryConstraint(new PasswordHashService(hashCost: 4)),
                ]),
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
            $guard,
            new SystemChangeWriter(new WriteOperationDispatcher($this->backend)),
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
