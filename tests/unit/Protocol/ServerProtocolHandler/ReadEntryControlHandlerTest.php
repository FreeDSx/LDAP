<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
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
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;

final class ReadEntryControlHandlerTest extends TestCase
{
    private ReadEntryControlHandler $subject;

    private Entry $entry;

    private TokenInterface $token;

    protected function setUp(): void
    {
        $this->entry = Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]);
        $this->token = BindToken::fromDn('cn=foo,dc=ex,dc=com');
        $this->subject = new ReadEntryControlHandler(
            new Schema(),
            new RuleBasedAccessControl(AclRules::fromEmpty(operations: self::searchAllowed())),
        );
    }

    public function test_pre_read_returns_null_without_the_control(): void
    {
        self::assertNull(
            $this->subject->preRead($this->entry, new ControlBag(), $this->token),
        );
    }

    public function test_post_read_returns_null_without_the_control(): void
    {
        self::assertNull(
            $this->subject->postRead($this->entry, new ControlBag(), $this->token),
        );
    }

    public function test_pre_read_returns_null_when_the_write_kept_no_entry(): void
    {
        self::assertNull(
            $this->subject->preRead(null, new ControlBag(new PreReadControl()), $this->token),
        );
    }

    public function test_pre_read_returns_a_response_control_with_the_entry(): void
    {
        $control = $this->subject->preRead(
            $this->entry,
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
        $control = $this->subject->postRead(
            Entry::fromArray('cn=foo,dc=ex,dc=com', [
                'cn' => ['foo'],
                'sn' => ['bar'],
            ]),
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

    public function test_the_control_is_isolated_from_later_mutation_of_the_entry(): void
    {
        $control = $this->subject->preRead(
            $this->entry,
            new ControlBag(new PreReadControl()),
            $this->token,
        );

        $this->entry->get('cn')?->add('changed');

        self::assertInstanceOf(PreReadResponseControl::class, $control);
        self::assertSame(
            ['foo'],
            $control->getEntry()->get('cn')?->getValues(),
        );
    }

    public function test_pre_read_omits_an_attribute_the_token_may_not_read(): void
    {
        $control = $this->denyingUserPassword()->preRead(
            Entry::fromArray('cn=foo,dc=ex,dc=com', [
                'cn' => ['foo'],
                'userPassword' => ['{SSHA}secret'],
            ]),
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
        $control = $this->denyingUserPassword()->postRead(
            Entry::fromArray('cn=foo,dc=ex,dc=com', [
                'cn' => ['foo'],
                'userPassword' => ['{SSHA}secret'],
            ]),
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
        $subject = new ReadEntryControlHandler(
            new Schema(),
            new RuleBasedAccessControl(AclRules::fromEmpty()),
        );

        self::assertNull($subject->preRead(
            $this->entry,
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
