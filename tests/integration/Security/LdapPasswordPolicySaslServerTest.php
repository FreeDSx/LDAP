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
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\PlainOptions;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

final class LdapPasswordPolicySaslServerTest extends ServerTestCase
{
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
