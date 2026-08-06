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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue\Response;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\PasswordPolicyResponseInterceptor;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyResponseInterceptorTest extends TestCase
{
    private PasswordPolicyContext $context;

    private PasswordPolicyResponseInterceptor $subject;

    protected function setUp(): void
    {
        $this->context = new PasswordPolicyContext();
        $this->context->setResponseRequested(true);
        $this->subject = new PasswordPolicyResponseInterceptor($this->context);
    }

    public function test_it_attaches_the_control_and_clears_when_the_context_has_a_payload(): void
    {
        $this->context->setOutcome(PasswordPolicyOutcome::allowWithGraceWarning(3));

        $response = $this->subject->intercept($this->bindResponse());

        $control = $response->controls()->get(Control::OID_PWD_POLICY);
        self::assertInstanceOf(
            PwdPolicyResponseControl::class,
            $control,
        );
        self::assertSame(
            3,
            $control->getGraceAttemptsRemaining(),
        );
        self::assertNull(
            $this->context->getOutcome(),
            'The context should be cleared after the control is attached.',
        );
    }

    public function test_it_does_not_leak_the_control_onto_a_later_message(): void
    {
        $this->context->setOutcome(PasswordPolicyOutcome::allowWithGraceWarning(3));

        $first = $this->subject->intercept($this->bindResponse());
        $second = $this->subject->intercept($this->bindResponse());

        self::assertTrue($first->controls()->has(Control::OID_PWD_POLICY));
        self::assertFalse(
            $second->controls()->has(Control::OID_PWD_POLICY),
            'Clearing on attach prevents the control leaking onto an unrelated later response.',
        );
    }

    public function test_it_is_a_no_op_when_the_context_is_empty(): void
    {
        $response = $this->subject->intercept($this->bindResponse());

        self::assertCount(
            0,
            $response->controls()->toArray(),
        );
    }

    public function test_it_is_a_no_op_for_a_payload_free_outcome(): void
    {
        $this->context->setOutcome(PasswordPolicyOutcome::allow());

        $response = $this->subject->intercept($this->bindResponse());

        self::assertCount(
            0,
            $response->controls()->toArray(),
        );
        self::assertNotNull(
            $this->context->getOutcome(),
            'A payload-free outcome is left intact since nothing was attached.',
        );
    }

    private function bindResponse(): LdapMessageResponse
    {
        return new LdapMessageResponse(
            1,
            new BindResponse(new LdapResult(ResultCode::SUCCESS)),
        );
    }
}
