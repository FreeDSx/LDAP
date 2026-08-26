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

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\PasswordPolicyResponseInterceptor;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\StorageReadBackend;
use FreeDSx\Ldap\Server\Backend\Write\PasswordPolicyWriteHandler;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriter;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestRouter;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerDispatchHandler;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\HistoryEntry;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

/**
 * In-process integration of a plain ldapmodify of userPassword flowing through the dispatch handler.
 */
final class PasswordPolicyPlainModifyEnforcementTest extends TestCase
{
    use ServerContainerTrait;

    private const NOW = '2026-05-20T12:00:00Z';

    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private FrozenClock $clock;

    private StorageReadBackend $backend;

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
        $handler = $this->dispatchHandler(
            new PasswordPolicy(quality: new PasswordQualityRules(inHistory: 5)),
            [PasswordPolicyOid::NAME_PWD_HISTORY => $this->historyValue('previous-pass')],
        );

        try {
            $handler->handleRequest(
                $this->modify('previous-pass'),
                $this->token(),
            );
            self::fail('Expected the reused password to be rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }

        $control = $this->context->buildResponseControl();
        self::assertInstanceOf(
            PwdPolicyResponseControl::class,
            $control,
        );
        self::assertSame(
            PwdPolicyError::PASSWORD_IN_HISTORY,
            $control->getError(),
        );
    }

    public function test_successful_change_persists_and_records_bookkeeping(): void
    {
        $handler = $this->dispatchHandler(
            new PasswordPolicy(quality: new PasswordQualityRules(inHistory: 3)),
            [PasswordPolicyOid::NAME_PWD_RESET => 'TRUE'],
        );

        $this->handle(
            $handler,
            $this->modify('a-fresh-password'),
            $this->token(),
        );

        $response = $this->response?->getResponse();
        self::assertInstanceOf(
            LdapResult::class,
            $response,
        );
        self::assertSame(
            ResultCode::SUCCESS,
            $response->getResultCode(),
        );

        $entry = $this->backend->get(new Dn(self::USER_DN));
        self::assertNotNull($entry);
        self::assertTrue(
            (new PasswordHashService(hashCost: 4))->verify(
                'a-fresh-password',
                (string) $entry->get('userPassword')?->firstValue(),
            ),
        );
        self::assertNotNull($entry->get(PasswordPolicyOid::NAME_PWD_CHANGED_TIME));
        self::assertNull(
            $entry->get(PasswordPolicyOid::NAME_PWD_RESET),
            'A successful change should clear pwdReset.',
        );
    }

    public function test_prehashed_value_rejected_when_check_quality_is_strict(): void
    {
        $handler = $this->dispatchHandler(
            new PasswordPolicy(quality: new PasswordQualityRules(
                minLength: 8,
                checkQuality: 2,
            )),
        );

        try {
            $handler->handleRequest(
                $this->modify('{SSHA}' . base64_encode('cannot-introspect-this')),
                $this->token(),
            );
            self::fail('Expected the prehashed value to be rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }

        $control = $this->context->buildResponseControl();
        self::assertInstanceOf(
            PwdPolicyResponseControl::class,
            $control,
        );
        self::assertSame(
            PwdPolicyError::INSUFFICIENT_PASSWORD_QUALITY,
            $control->getError(),
        );
    }

    public function test_safe_modify_with_wrong_old_password_is_rejected(): void
    {
        $handler = $this->dispatchHandler(
            new PasswordPolicy(change: new PasswordChangeRules(safeModify: true)),
        );

        try {
            $handler->handleRequest(
                $this->modifyWithOld('wrong-old', 'a-fresh-password'),
                $this->token(),
            );
            self::fail('Expected the safe-modify to be rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_CREDENTIALS,
                $e->getCode(),
            );
        }

        $entry = $this->backend->get(new Dn(self::USER_DN));
        self::assertSame(
            'original-pass',
            $entry?->get('userPassword')?->firstValue(),
            'A rejected safe-modify must not alter the stored password.',
        );
    }

    public function test_safe_modify_with_correct_old_password_succeeds(): void
    {
        $handler = $this->dispatchHandler(
            new PasswordPolicy(change: new PasswordChangeRules(safeModify: true)),
        );

        $this->handle(
            $handler,
            $this->modifyWithOld('original-pass', 'a-fresh-password'),
            $this->token(),
        );

        $response = $this->response?->getResponse();
        self::assertInstanceOf(
            LdapResult::class,
            $response,
        );
        self::assertSame(
            ResultCode::SUCCESS,
            $response->getResultCode(),
        );
    }

    public function test_self_password_modify_lifts_the_session_must_change_restriction(): void
    {
        $handler = $this->dispatchHandler(
            new PasswordPolicy(),
            [PasswordPolicyOid::NAME_PWD_RESET => 'TRUE'],
        );

        $token = $this->token();
        $token->markMustChangePassword();

        $this->handle(
            $handler,
            $this->modify('a-fresh-password'),
            $token,
        );

        $response = $this->response?->getResponse();
        self::assertInstanceOf(
            LdapResult::class,
            $response,
        );
        self::assertSame(
            ResultCode::SUCCESS,
            $response->getResultCode(),
        );
        self::assertFalse(
            $token->mustChangePassword(),
            'A successful self password modify must lift the session restriction without a rebind.',
        );
    }

    public function test_add_with_a_password_below_the_minimum_length_is_rejected(): void
    {
        $handler = $this->dispatchHandler(
            new PasswordPolicy(quality: new PasswordQualityRules(
                minLength: 8,
                checkQuality: 2,
            )),
        );

        try {
            $handler->handleRequest(
                $this->add('cn=new,dc=foo,dc=bar', 'short'),
                $this->token(),
            );
            self::fail('Expected the short password to be rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }
    }

    /**
     * An empty value must reach the quality check rather than read as no password being set.
     */
    public function test_add_with_an_empty_password_is_rejected_by_the_minimum_length(): void
    {
        $handler = $this->dispatchHandler(
            new PasswordPolicy(quality: new PasswordQualityRules(
                minLength: 8,
                checkQuality: 2,
            )),
        );

        try {
            $handler->handleRequest(
                $this->add('cn=new,dc=foo,dc=bar', ''),
                $this->token(),
            );
            self::fail('Expected the empty password to be rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }
    }

    public function test_add_stamps_the_password_changed_time(): void
    {
        $handler = $this->dispatchHandler(new PasswordPolicy(quality: new PasswordQualityRules(inHistory: 3)));

        $this->handle(
            $handler,
            $this->add('cn=new,dc=foo,dc=bar', 'a-fresh-password'),
            $this->token(),
        );

        $entry = $this->backend->get(new Dn('cn=new,dc=foo,dc=bar'));
        self::assertNotNull($entry);
        self::assertNotNull(
            $entry->get(PasswordPolicyOid::NAME_PWD_CHANGED_TIME),
            'Without pwdChangedTime the password has no age, so pwdMaxAge can never expire it.',
        );
    }

    public function test_add_by_an_administrator_stamps_pwd_reset_when_must_change_is_set(): void
    {
        $handler = $this->dispatchHandler(
            new PasswordPolicy(change: new PasswordChangeRules(mustChange: true)),
        );

        $this->handle(
            $handler,
            $this->add('cn=new,dc=foo,dc=bar', 'a-fresh-password'),
            $this->token(),
        );

        $entry = $this->backend->get(new Dn('cn=new,dc=foo,dc=bar'));
        self::assertSame(
            'TRUE',
            $entry?->get(PasswordPolicyOid::NAME_PWD_RESET)?->firstValue(),
        );
    }

    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::cheaplyHashed();
    }

    private function add(
        string $dn,
        string $password,
    ): LdapMessageRequest {
        return new LdapMessageRequest(
            1,
            new AddRequest(Entry::fromArray(
                $dn,
                [
                    'objectClass' => ['inetOrgPerson'],
                    'cn' => ['new'],
                    'sn' => ['New'],
                    'userPassword' => [$password],
                ],
            )),
        );
    }

    /**
     * @param array<string, string> $userAttrs
     */
    private function dispatchHandler(
        PasswordPolicy $policy,
        array $userAttrs = [],
    ): ServerDispatchHandler {
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
        ]));
        $this->backend = $container->get(StorageReadBackend::class);

        $guard = new PasswordPolicyChangeGuard(
            $this->fromContainer(
                PasswordPolicyEngine::class,
                [ClockInterface::class => $this->clock],
            ),
            new PasswordPolicyResolver(
                $this->backend,
                null,
                $policy,
            ),
            $this->context,
            new EventLogger(null),
        );
        $writes = $container->get(WriteOperationDispatcher::class);
        $policyWriteHandler = new PasswordPolicyWriteHandler(
            $this->backend,
            $writes,
            $guard,
            new SystemChangeWriter($writes),
        );

        return new ServerDispatchHandler(
            backend: $this->backend,
            router: new WriteRequestRouter($policyWriteHandler),
            accessControl: $this->createMock(AccessControlInterface::class),
            schema: new Schema(),
        );
    }

    private function handle(
        ServerDispatchHandler $handler,
        LdapMessageRequest $request,
        TokenInterface $token,
    ): void {
        $stream = $handler->handleRequest($request, $token);
        $messages = [...$stream->messages];
        self::assertCount(1, $messages);
        $this->response = (new PasswordPolicyResponseInterceptor($this->context))->intercept($messages[0]);
    }

    private function modify(string $newPassword): LdapMessageRequest
    {
        return new LdapMessageRequest(
            1,
            new ModifyRequest(
                self::USER_DN,
                Change::replace('userPassword', $newPassword),
            ),
        );
    }

    private function modifyWithOld(
        string $oldPassword,
        string $newPassword,
    ): LdapMessageRequest {
        return new LdapMessageRequest(
            1,
            new ModifyRequest(
                self::USER_DN,
                Change::delete('userPassword', $oldPassword),
                Change::add('userPassword', $newPassword),
            ),
        );
    }

    private function token(): BindToken
    {
        return BindToken::fromDn(
            self::USER_DN,
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
