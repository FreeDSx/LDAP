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

namespace Tests\Integration\FreeDSx\Ldap\Security;

use DateInterval;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\PasswordPolicyResponseInterceptor;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\DnBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyService;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
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
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPasswordModifyHandler;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

/**
 * In-process integration of RFC 3062 password-modify policy enforcement.
 */
final class PasswordPolicyChangeEnforcementTest extends TestCase
{
    private const NOW = '2026-05-20T12:00:00Z';

    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private const OLD_PASSWORD = '12345';

    private FrozenClock $clock;

    private WritableStorageBackend $backend;

    private PasswordPolicyContext $context;

    private ?LdapMessageResponse $response = null;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString(self::NOW);
        $this->context = new PasswordPolicyContext();
        $this->context->setResponseRequested(true);
    }

    public function test_reused_password_is_rejected_with_history_control(): void
    {
        $handler = $this->handlerFor(
            new PasswordPolicy(quality: new PasswordQualityRules(inHistory: 5)),
            [PasswordPolicyOid::NAME_PWD_HISTORY => $this->historyValue('previous-pass')],
        );

        $this->handle(
            $handler,
            $this->request(self::OLD_PASSWORD, 'previous-pass'),
            $this->selfToken(),
        );

        $this->assertResultCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->assertControlError(PwdPolicyError::PASSWORD_IN_HISTORY);
    }

    public function test_change_within_min_age_is_rejected(): void
    {
        $handler = $this->handlerFor(
            new PasswordPolicy(change: new PasswordChangeRules(minAge: 3600)),
            [PasswordPolicyOid::NAME_PWD_CHANGED_TIME => $this->minutesAgo(30)],
        );

        $this->handle(
            $handler,
            $this->request(self::OLD_PASSWORD, 'a-fresh-password'),
            $this->selfToken(),
        );

        $this->assertResultCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->assertControlError(PwdPolicyError::PASSWORD_TOO_YOUNG);
    }

    public function test_safe_modify_without_old_password_is_rejected(): void
    {
        $handler = $this->handlerFor(
            new PasswordPolicy(change: new PasswordChangeRules(safeModify: true)),
        );

        $this->handle(
            $handler,
            $this->request(null, 'a-fresh-password'),
            $this->selfToken(),
        );

        $this->assertResultCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->assertControlError(PwdPolicyError::MUST_SUPPLY_OLD_PASSWORD);
    }

    public function test_self_change_blocked_when_not_allowed(): void
    {
        $handler = $this->handlerFor(
            new PasswordPolicy(change: new PasswordChangeRules(allowUserChange: false)),
        );

        $this->handle(
            $handler,
            $this->request(self::OLD_PASSWORD, 'a-fresh-password'),
            $this->selfToken(),
        );

        $this->assertResultCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);
        $this->assertControlError(PwdPolicyError::PASSWORD_MOD_NOT_ALLOWED);
    }

    public function test_successful_change_persists_password_and_clears_reset(): void
    {
        $handler = $this->handlerFor(
            new PasswordPolicy(quality: new PasswordQualityRules(inHistory: 3)),
            [PasswordPolicyOid::NAME_PWD_RESET => 'TRUE'],
        );

        $this->handle(
            $handler,
            $this->request(self::OLD_PASSWORD, 'a-fresh-password'),
            $this->selfToken(),
        );

        self::assertInstanceOf(
            PasswordModifyResponse::class,
            $this->response?->getResponse(),
        );

        $entry = $this->backend->get(new Dn(self::USER_DN));
        self::assertNotNull($entry);
        self::assertTrue(
            (new PasswordHashService(hashCost: 4))->verify(
                'a-fresh-password',
                (string) $entry->get('userPassword')?->firstValue(),
            ),
            'The new password should be persisted and verifiable.',
        );
        self::assertNotNull($entry->get(PasswordPolicyOid::NAME_PWD_CHANGED_TIME));
        self::assertNotNull($entry->get(PasswordPolicyOid::NAME_PWD_HISTORY));
        self::assertNull(
            $entry->get(PasswordPolicyOid::NAME_PWD_RESET),
            'pwdReset should be cleared after a successful change.',
        );
    }

    public function test_admin_reset_sets_pwd_reset_when_policy_requires_change(): void
    {
        $handler = $this->handlerFor(
            new PasswordPolicy(change: new PasswordChangeRules(mustChange: true)),
        );

        $this->handle(
            $handler,
            $this->request(
                null,
                'admin-set-password',
                self::USER_DN,
            ),
            $this->adminToken(),
        );

        self::assertInstanceOf(
            PasswordModifyResponse::class,
            $this->response?->getResponse(),
        );

        $entry = $this->backend->get(new Dn(self::USER_DN));
        self::assertSame(
            'TRUE',
            $entry?->get(PasswordPolicyOid::NAME_PWD_RESET)?->firstValue(),
            'An administrative reset under pwdMustChange must force a password change.',
        );
    }

    public function test_self_change_clears_pwd_reset_even_under_must_change_policy(): void
    {
        $handler = $this->handlerFor(
            new PasswordPolicy(change: new PasswordChangeRules(mustChange: true)),
            [PasswordPolicyOid::NAME_PWD_RESET => 'TRUE'],
        );

        $this->handle(
            $handler,
            $this->request(
                self::OLD_PASSWORD,
                'a-fresh-password',
            ),
            $this->selfToken(),
        );

        $entry = $this->backend->get(new Dn(self::USER_DN));
        self::assertNull(
            $entry?->get(PasswordPolicyOid::NAME_PWD_RESET),
            'A self-change satisfies the reset requirement and must clear pwdReset.',
        );
    }

    public function test_self_change_lifts_the_session_must_change_restriction(): void
    {
        $handler = $this->handlerFor(
            new PasswordPolicy(),
            [PasswordPolicyOid::NAME_PWD_RESET => 'TRUE'],
        );

        $token = $this->selfToken();
        $token->markMustChangePassword();

        $this->handle(
            $handler,
            $this->request(
                self::OLD_PASSWORD,
                'a-fresh-password',
            ),
            $token,
        );

        self::assertInstanceOf(
            PasswordModifyResponse::class,
            $this->response?->getResponse(),
        );
        self::assertFalse(
            $token->mustChangePassword(),
            'A successful self-change must lift the session restriction without a rebind.',
        );
    }

    /**
     * @param array<string, string> $extra
     */
    private function handlerFor(
        PasswordPolicy $policy,
        array $extra = [],
    ): ServerPasswordModifyHandler {
        $this->backend = new WritableStorageBackend(new InMemoryStorage([
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
                    'userPassword' => [self::OLD_PASSWORD],
                ] + $extra,
            ),
        ]));

        return new ServerPasswordModifyHandler(
            service: new PasswordModifyService(
                targetResolver: new PasswordModifyTargetResolver(
                    $this->backend,
                    new DnBindNameResolver(),
                ),
                accessControl: $this->createMock(AccessControlInterface::class),
                writeDispatcher: new WriteOperationDispatcher($this->backend),
                changeGuard: new PasswordPolicyChangeGuard(
                    $this->engine(),
                    new PasswordPolicyResolver(
                        $this->backend,
                        null,
                        $policy,
                    ),
                    $this->context,
                    new EventLogger(null, EventLogPolicy::all()),
                ),
                passwordPolicyContext: $this->context,
            ),
        );
    }

    private function engine(): PasswordPolicyEngine
    {
        return new PasswordPolicyEngine(
            clock: $this->clock,
            changeConstraints: new PasswordChangeConstraintChain([
                new AllowUserChangeConstraint(),
                new SafeModifyConstraint(),
                new MinAgeConstraint($this->clock),
                new QualityConstraint(new DefaultPasswordQualityChecker()),
                new HistoryConstraint(new PasswordHashService(hashCost: 4)),
            ]),
        );
    }

    private function handle(
        ServerPasswordModifyHandler $handler,
        LdapMessageRequest $request,
        TokenInterface $token,
    ): void {
        $stream = $handler->handleRequest($request, $token);
        $messages = [...$stream->messages];
        self::assertCount(1, $messages);
        $this->response = (new PasswordPolicyResponseInterceptor($this->context))->intercept($messages[0]);
    }

    private function request(
        ?string $oldPassword,
        string $newPassword,
        ?string $userIdentity = null,
    ): LdapMessageRequest {
        return new LdapMessageRequest(
            1,
            new PasswordModifyRequest(
                $userIdentity,
                $oldPassword,
                $newPassword,
            ),
        );
    }

    private function selfToken(): BindToken
    {
        return BindToken::fromDn(self::USER_DN);
    }

    private function adminToken(): BindToken
    {
        return BindToken::fromDn(
            'cn=admin,dc=foo,dc=bar',
        );
    }

    private function minutesAgo(int $minutes): string
    {
        return GeneralizedTime::format(
            $this->clock
                ->now()
                ->sub(new DateInterval(sprintf('PT%dM', $minutes))),
        );
    }

    private function historyValue(string $plaintext): string
    {
        return HistoryEntry::forStoredPassword(
            $this->clock->now(),
            '{BCRYPT}' . password_hash($plaintext, PASSWORD_BCRYPT, ['cost' => 4]),
        )->encode();
    }

    private function assertResultCode(int $expected): void
    {
        $response = $this->response?->getResponse();
        self::assertInstanceOf(
            LdapResult::class,
            $response,
        );
        self::assertSame(
            $expected,
            $response->getResultCode(),
        );
    }

    private function assertControlError(int $expectedError): void
    {
        $control = $this->response?->controls()->getByClass(PwdPolicyResponseControl::class);
        self::assertInstanceOf(
            PwdPolicyResponseControl::class,
            $control,
        );
        self::assertSame(
            $expectedError,
            $control->getError(),
        );
    }
}
