<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ReadEntryControlHandler;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ReadEntryControlHandlerTest extends TestCase
{
    private LdapBackendInterface&MockObject $backend;

    private ReadEntryControlHandler $subject;

    private Dn $dn;

    private TokenInterface $token;

    protected function setUp(): void
    {
        $this->backend = $this->createMock(LdapBackendInterface::class);
        $this->dn = new Dn('cn=foo,dc=ex,dc=com');
        $this->token = BindToken::fromDn('cn=foo,dc=ex,dc=com');
        $this->subject = new ReadEntryControlHandler(
            $this->backend,
            new Schema(),
            new RuleBasedAccessControl(AclRules::fromEmpty(operations: self::searchAllowed())),
        );
    }

    public function test_pre_read_returns_null_without_the_control(): void
    {
        $this->backend
            ->expects(self::never())
            ->method('get');

        self::assertNull(
            $this->subject->preRead($this->dn, new ControlBag(), $this->token),
        );
    }

    public function test_post_read_returns_null_without_the_control(): void
    {
        self::assertNull(
            $this->subject->postRead($this->dn, new ControlBag(), $this->token),
        );
    }

    public function test_pre_read_returns_null_when_the_entry_is_absent(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(null);

        self::assertNull(
            $this->subject->preRead($this->dn, new ControlBag(new PreReadControl()), $this->token),
        );
    }

    public function test_pre_read_returns_a_response_control_with_the_entry(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]));

        $control = $this->subject->preRead(
            $this->dn,
            new ControlBag(new PreReadControl()),
            $this->token,
        );

        self::assertInstanceOf(PreReadResponseControl::class, $control);
        self::assertSame(
            'cn=foo,dc=ex,dc=com',
            $control->getEntry()->getDn()->toString(),
        );
    }

    public function test_post_read_projects_only_the_requested_attributes(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', [
                'cn' => ['foo'],
                'sn' => ['bar'],
            ]));

        $control = $this->subject->postRead(
            $this->dn,
            new ControlBag(new PostReadControl('cn')),
            $this->token,
        );

        self::assertInstanceOf(PostReadResponseControl::class, $control);
        self::assertSame(
            ['cn'],
            array_map(
                static fn($attr): string => $attr->getName(),
                $control->getEntry()->getAttributes(),
            ),
        );
    }

    public function test_the_snapshot_is_isolated_from_later_mutation_of_the_stored_entry(): void
    {
        $stored = Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]);
        $this->backend
            ->method('get')
            ->willReturn($stored);

        $control = $this->subject->preRead(
            $this->dn,
            new ControlBag(new PreReadControl()),
            $this->token,
        );

        // Mutate the stored entry in place after the snapshot was taken.
        $stored->get('cn')?->add('changed');

        self::assertInstanceOf(PreReadResponseControl::class, $control);
        self::assertSame(
            ['foo'],
            $control->getEntry()->get('cn')?->getValues(),
        );
    }

    public function test_pre_read_omits_an_attribute_the_token_may_not_read(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', [
                'cn' => ['foo'],
                'userPassword' => ['{SSHA}secret'],
            ]));

        $control = $this->denyingUserPassword()->preRead(
            $this->dn,
            new ControlBag(new PreReadControl()),
            $this->token,
        );

        self::assertInstanceOf(PreReadResponseControl::class, $control);
        self::assertNull($control->getEntry()->get('userPassword'));
        self::assertSame(
            ['foo'],
            $control->getEntry()->get('cn')?->getValues(),
        );
    }

    public function test_post_read_cannot_name_an_attribute_the_token_may_not_read(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', [
                'cn' => ['foo'],
                'userPassword' => ['{SSHA}secret'],
            ]));

        $control = $this->denyingUserPassword()->postRead(
            $this->dn,
            new ControlBag(new PostReadControl('userPassword')),
            $this->token,
        );

        self::assertInstanceOf(PostReadResponseControl::class, $control);
        self::assertSame(
            [],
            $control->getEntry()->getAttributes(),
        );
    }

    public function test_no_control_is_returned_when_the_token_may_not_read_the_target(): void
    {
        $this->backend
            ->method('get')
            ->willReturn(Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]));

        $subject = new ReadEntryControlHandler(
            $this->backend,
            new Schema(),
            new RuleBasedAccessControl(AclRules::fromEmpty()),
        );

        self::assertNull($subject->preRead(
            $this->dn,
            new ControlBag(new PreReadControl()),
            $this->token,
        ));
    }

    /**
     * @return list<OperationRule>
     */
    private static function searchAllowed(): array
    {
        return [
            OperationRule::allow(
                Subject::anyone(),
                Target::any(),
                OperationType::Search,
            ),
        ];
    }

    private function denyingUserPassword(): ReadEntryControlHandler
    {
        return new ReadEntryControlHandler(
            $this->backend,
            new Schema(),
            new RuleBasedAccessControl(AclRules::fromEmpty(
                operations: self::searchAllowed(),
                attributes: [
                    AttributeRule::deny(
                        Subject::anyone(),
                        Target::any(),
                        'userPassword',
                    )->forRead(),
                ],
            )),
        );
    }
}
