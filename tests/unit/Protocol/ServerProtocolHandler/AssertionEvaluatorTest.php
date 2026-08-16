<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\AssertionControl;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use Tests\Support\FreeDSx\Ldap\Backend\Storage\FilterEvaluatorFactoryTrait;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class AssertionEvaluatorTest extends TestCase
{
    use FilterEvaluatorFactoryTrait;

    private LdapBackendInterface&MockObject $backend;

    private AssertionEvaluator $subject;

    private Dn $targetDn;

    private TokenInterface $token;

    protected function setUp(): void
    {
        $this->backend = $this->createMock(LdapBackendInterface::class);
        $this->targetDn = new Dn('cn=foo,dc=ex,dc=com');
        $this->token = BindToken::fromDn('cn=foo,dc=ex,dc=com');
        $this->subject = new AssertionEvaluator(
            $this->makeFilterEvaluator(),
            $this->backend,
            new RuleBasedAccessControl(AclRules::fromEmpty()),
        );
    }

    public function test_it_does_nothing_when_no_assertion_control_is_present(): void
    {
        $this->backend
            ->expects(self::never())
            ->method('get');

        $this->subject->assertSatisfied(
            $this->targetDn,
            new ControlBag(),
            $this->token,
        );
    }

    public function test_it_passes_when_the_assertion_matches_the_target_entry(): void
    {
        $this->backend
            ->method('get')
            ->with($this->targetDn)
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]));

        $this->subject->assertSatisfied(
            $this->targetDn,
            new ControlBag(new AssertionControl(Filters::equal('cn', 'foo'))),
            $this->token,
        );
    }

    public function test_it_throws_assertion_failed_when_the_assertion_does_not_match(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ASSERTION_FAILED);

        $this->subject->assertSatisfied(
            $this->targetDn,
            new ControlBag(new AssertionControl(Filters::equal('cn', 'bar'))),
            $this->token,
        );
    }

    public function test_it_does_not_throw_when_the_target_entry_is_absent(): void
    {
        $this->backend
            ->expects(self::once())
            ->method('get')
            ->with($this->targetDn)
            ->willReturn(null);

        $this->subject->assertSatisfied(
            $this->targetDn,
            new ControlBag(new AssertionControl(Filters::equal('cn', 'bar'))),
            $this->token,
        );
    }

    public function test_an_assertion_on_an_unreadable_attribute_cannot_match(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', [
                'cn' => ['foo'],
                'userPassword' => ['{SSHA}secret'],
            ]));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ASSERTION_FAILED);

        $this->denyingUserPassword()->assertSatisfied(
            $this->targetDn,
            new ControlBag(new AssertionControl(Filters::equal('userPassword', '{SSHA}secret'))),
            $this->token,
        );
    }

    public function test_a_substring_assertion_on_an_unreadable_attribute_cannot_probe_its_value(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', [
                'cn' => ['foo'],
                'userPassword' => ['{SSHA}secret'],
            ]));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ASSERTION_FAILED);

        $this->denyingUserPassword()->assertSatisfied(
            $this->targetDn,
            new ControlBag(new AssertionControl(Filters::startsWith('userPassword', '{SSHA}s'))),
            $this->token,
        );
    }

    public function test_a_readable_attribute_still_asserts_normally_under_the_same_rules(): void
    {
        $this->expectNotToPerformAssertions();
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', [
                'cn' => ['foo'],
                'userPassword' => ['{SSHA}secret'],
            ]));

        $this->denyingUserPassword()->assertSatisfied(
            $this->targetDn,
            new ControlBag(new AssertionControl(Filters::equal('cn', 'foo'))),
            $this->token,
        );
    }

    private function denyingUserPassword(): AssertionEvaluator
    {
        return new AssertionEvaluator(
            $this->makeFilterEvaluator(),
            $this->backend,
            new RuleBasedAccessControl(AclRules::fromEmpty(attributes: [
                AttributeRule::deny(
                    Subject::anyone(),
                    Target::any(),
                    'userPassword',
                )->forRead(),
            ])),
        );
    }
}
