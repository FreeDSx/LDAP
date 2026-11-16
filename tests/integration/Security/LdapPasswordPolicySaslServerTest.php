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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\PlainOptions;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\PasswordPolicyServerTrait;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

final class LdapPasswordPolicySaslServerTest extends ServerTestCase
{
    use PasswordPolicyServerTrait;
    use RawClientQueueTrait;

    public function setUp(): void
    {
        $this->setServerMode('ldap-password-policy');

        parent::setUp();

        $this->createServerProcess('tcp');
    }

    public function testSaslBindUnderResetCarriesThePasswordPolicyControl(): void
    {
        $response = $this->ldapClient()->bindSasl(
            (new PlainOptions())->setUsername('reset-user')->setPassword('12345'),
            MechanismName::PLAIN,
            controls: Controls::pwdPolicy(),
        );

        $control = $response->controls()->getByClass(PwdPolicyResponseControl::class);

        $this->assertInstanceOf(
            PwdPolicyResponseControl::class,
            $control,
            'A SASL bind under pwdReset should carry the password policy response control.',
        );
        $this->assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $control->getError(),
        );
    }

    public function testAnUnsupportedCriticalControlOnASaslContinuationIsRefused(): void
    {
        $message = $this->completePlainExchange(
            'user',
            new Control('1.2.3.4.5.6.7.8.9', true),
        );

        $this->assertSame(
            ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            $this->resultCodeOf($message),
        );
    }

    public function testThePasswordPolicyControlOnASaslContinuationIsAnswered(): void
    {
        $message = $this->completePlainExchange(
            'reset-user',
            Controls::pwdPolicy(),
        );
        $control = $message->controls()->getByClass(PwdPolicyResponseControl::class);

        $this->assertSame(
            ResultCode::SUCCESS,
            $this->resultCodeOf($message),
        );
        $this->assertInstanceOf(
            PwdPolicyResponseControl::class,
            $control,
        );
        $this->assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $control->getError(),
        );
    }

    public function testCleanSaslBindCarriesNoControl(): void
    {
        $response = $this->ldapClient()->bindSasl(
            (new PlainOptions())->setUsername('user')->setPassword('12345'),
            MechanismName::PLAIN,
        );

        $this->assertFalse($response->controls()->has(Control::OID_PWD_POLICY));
    }

    public function testASaslBindToALockedAccountAnswersTheSameForTheRightAndAWrongPassword(): void
    {
        $this->useSubentryPolicyServer();
        $this->failBinds(
            'cn=inside-user,ou=secure,dc=foo,dc=bar',
            self::MAX_FAILURE,
        );

        $right = $this->failedPlainBind(
            'inside-user',
            '12345',
        );

        self::assertSame(
            ResultCode::INVALID_CREDENTIALS,
            $right[0],
        );
        self::assertSame(
            $right,
            $this->failedPlainBind(
                'inside-user',
                'not-the-password',
            ),
        );

        $this->ldapClient()->bind(
            'cn=admin,dc=foo,dc=bar',
            '12345',
        );
        $entry = $this->ldapClient()->read(
            'cn=inside-user,ou=secure,dc=foo,dc=bar',
            [PasswordPolicyOid::NAME_PWD_FAILURE_TIME],
        );

        self::assertNotNull($entry);
        self::assertCount(
            self::MAX_FAILURE,
            $entry->get(PasswordPolicyOid::NAME_PWD_FAILURE_TIME)?->getValues() ?? [],
        );
    }

    public function testAProxiedSaslBindByALockedIdentityIsRefusedAsAWrongPassword(): void
    {
        $this->useSubentryPolicyServer();
        $this->failBinds(
            'cn=admin,dc=foo,dc=bar',
            self::MAX_FAILURE,
        );
        $authzId = 'dn:cn=inside-user,ou=secure,dc=foo,dc=bar';

        $right = $this->failedPlainBind(
            'admin',
            '12345',
            $authzId,
        );

        self::assertSame(
            ResultCode::INVALID_CREDENTIALS,
            $right[0],
        );
        self::assertSame(
            $right,
            $this->failedPlainBind(
                'admin',
                'not-the-password',
                $authzId,
            ),
        );
    }

    public function testALockedIdentityIsRefusedBeforeItsAuthzIdIsConsidered(): void
    {
        $this->useSubentryPolicyServer(['--report-account-lock']);
        $this->failBinds(
            'cn=inside-user,ou=secure,dc=foo,dc=bar',
            self::MAX_FAILURE,
        );

        $queue = $this->rawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            1,
            new SaslBindRequest(
                MechanismName::PLAIN->value,
                "dn:cn=nobody,dc=foo,dc=bar\x00inside-user\x0012345",
            ),
            Controls::pwdPolicy(),
        ));
        $message = $queue->getMessage(1);
        $queue->close();

        self::assertSame(
            ResultCode::INVALID_CREDENTIALS,
            $this->resultCodeOf($message),
        );
        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $message->controls()->getByClass(PwdPolicyResponseControl::class)?->getError(),
        );
    }

    public function testAProxiedSaslBindRecordsNothingOnTheAssumedIdentity(): void
    {
        $this->useSubentryPolicyServer();
        $target = 'cn=inside-user,ou=secure,dc=foo,dc=bar';

        $this->ldapClient()->bindSasl(
            (new PlainOptions())->setUsername('admin')->setPassword('12345')->setAuthzId('dn:' . $target),
            MechanismName::PLAIN,
        );

        self::assertSame(
            'dn:' . $target,
            $this->ldapClient()->whoami(),
        );

        $this->ldapClient()->bind(
            'cn=admin,dc=foo,dc=bar',
            '12345',
        );
        $entry = $this->ldapClient()->read(
            $target,
            [PasswordPolicyOid::NAME_PWD_LAST_SUCCESS],
        );

        self::assertNotNull($entry);
        self::assertNull($entry->get(PasswordPolicyOid::NAME_PWD_LAST_SUCCESS));
    }

    public function testAnIdentityThatMustChangeItsPasswordMayNotAssumeAnother(): void
    {
        $queue = $this->rawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            1,
            new SaslBindRequest(
                MechanismName::PLAIN->value,
                "dn:cn=user,dc=foo,dc=bar\x00reset-proxy\x0012345",
            ),
            Controls::pwdPolicy(),
        ));
        $message = $queue->getMessage(1);
        $queue->close();

        self::assertSame(
            ResultCode::INVALID_CREDENTIALS,
            $this->resultCodeOf($message),
        );
        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $message->controls()->getByClass(PwdPolicyResponseControl::class)?->getError(),
        );
    }

    /**
     * @return array{int, string}
     */
    private function failedPlainBind(
        string $user,
        string $password,
        string $authzId = '',
    ): array {
        try {
            $this->ldapClient()->bindSasl(
                (new PlainOptions())->setUsername($user)->setPassword($password)->setAuthzId($authzId),
                MechanismName::PLAIN,
            );
        } catch (BindException $e) {
            return [
                $e->getCode(),
                $e->getMessage(),
            ];
        }

        self::fail('The SASL bind should have been refused.');
    }

    private function completePlainExchange(
        string $user,
        Control $continuationControl,
    ): LdapMessageResponse {
        $queue = $this->rawQueue();

        $queue->sendMessage(new LdapMessageRequest(
            1,
            new SaslBindRequest(MechanismName::PLAIN->value),
        ));
        $this->assertSame(
            ResultCode::SASL_BIND_IN_PROGRESS,
            $this->resultCodeOf($queue->getMessage(1)),
            'PLAIN without credentials should ask for them.',
        );

        $queue->sendMessage(new LdapMessageRequest(
            2,
            new SaslBindRequest(
                MechanismName::PLAIN->value,
                "\x00{$user}\x0012345",
            ),
            $continuationControl,
        ));
        $message = $queue->getMessage(2);
        $queue->close();

        return $message;
    }

    private function resultCodeOf(LdapMessageResponse $message): int
    {
        $response = $message->getResponse();
        self::assertInstanceOf(
            BindResponse::class,
            $response,
        );

        return $response->getResultCode();
    }
}
