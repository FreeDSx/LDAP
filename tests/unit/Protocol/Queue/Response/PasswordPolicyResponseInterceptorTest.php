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

    public function test_it_consumes_a_payload_free_outcome_without_attaching_a_control(): void
    {
        $this->context->setOutcome(PasswordPolicyOutcome::allow());

        $response = $this->subject->intercept($this->bindResponse());

        self::assertCount(
            0,
            $response->controls()->toArray(),
        );
        self::assertNull(
            $this->context->getOutcome(),
            'An outcome describes one operation, so the response it rode out with consumes it either way.',
        );
    }

    public function test_an_unconsumed_outcome_does_not_survive_to_a_later_response(): void
    {
        // The client asked for nothing, so this outcome produces no control and would otherwise be left behind.
        $this->context->setResponseRequested(false);
        $this->context->setOutcome(PasswordPolicyOutcome::allowWithGraceWarning(3));
        $this->subject->intercept($this->bindResponse());

        $this->context->setResponseRequested(true);
        $later = $this->subject->intercept($this->bindResponse());

        self::assertFalse(
            $later->controls()->has(Control::OID_PWD_POLICY),
            'A later response carried policy state belonging to the operation before it.',
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
