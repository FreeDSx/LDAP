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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\PrivilegedBypassAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\ManagerToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class PrivilegedBypassAccessControlTest extends TestCase
{
    private AccessControlInterface&MockObject $inner;

    private PrivilegedBypassAccessControl $subject;

    private ManagerToken $manager;

    private BindToken $user;

    protected function setUp(): void
    {
        $this->inner = $this->createMock(AccessControlInterface::class);
        $this->subject = new PrivilegedBypassAccessControl($this->inner);
        $this->manager = new ManagerToken(new Dn('cn=manager'));
        $this->user = BindToken::fromDn('cn=user,dc=foo,dc=bar');
    }

    public function test_privileged_token_bypasses_every_authorization(): void
    {
        $this->inner
            ->expects(self::never())
            ->method('authorizeOperation');
        $this->inner
            ->expects(self::never())
            ->method('authorizeAttribute');
        $this->inner
            ->expects(self::never())
            ->method('authorizeControl');
        $this->inner
            ->expects(self::never())
            ->method('authorizeExtendedOperation');

        $dn = new Dn('cn=other,dc=foo,dc=bar');
        $this->subject->authorizeOperation(
            OperationType::Modify,
            $this->manager,
            $dn,
        );
        $this->subject->authorizeAttribute(
            $this->manager,
            $dn,
            'userPassword',
            AttributeAccess::Write,
        );
        $this->subject->authorizeControl(
            $this->manager,
            $dn,
            '1.2.3',
        );
        $this->subject->authorizeExtendedOperation(
            $this->manager,
            '1.2.3.4',
        );

        $this->addToAssertionCount(1);
    }

    public function test_privileged_token_may_use_any_control_and_keeps_the_whole_entry(): void
    {
        $this->inner
            ->expects(self::never())
            ->method('mayUseControl');
        $this->inner
            ->expects(self::never())
            ->method('filterEntry');
        $this->inner
            ->expects(self::never())
            ->method('isEntryVisible');

        $entry = new Entry(new Dn('cn=other,dc=foo,dc=bar'));

        self::assertTrue($this->subject->mayUseControl(
            $this->manager,
            '1.2.3',
        ));
        self::assertSame(
            $entry,
            $this->subject->filterEntry(
                $this->manager,
                $entry,
            ),
        );
        self::assertTrue($this->subject->isEntryVisible(
            $this->manager,
            $entry,
        ));
    }

    public function test_privileged_token_has_confidential_access_without_consulting_the_inner_policy(): void
    {
        $this->inner
            ->expects(self::never())
            ->method('hasConfidentialAccess');

        self::assertTrue($this->subject->hasConfidentialAccess(
            $this->manager,
            'userPassword',
        ));
    }

    public function test_non_privileged_confidential_access_delegates_to_the_inner_policy(): void
    {
        $this->inner
            ->expects(self::once())
            ->method('hasConfidentialAccess')
            ->with(
                $this->user,
                'userPassword',
            )
            ->willReturn(false);

        self::assertFalse($this->subject->hasConfidentialAccess(
            $this->user,
            'userPassword',
        ));
    }

    public function test_non_privileged_token_delegates_to_the_inner_policy(): void
    {
        $this->inner
            ->expects(self::once())
            ->method('authorizeExtendedOperation')
            ->with(
                $this->user,
                '1.2.3.4',
            );

        $this->subject->authorizeExtendedOperation(
            $this->user,
            '1.2.3.4',
        );
    }

    public function test_non_privileged_entry_visibility_delegates_to_the_inner_policy(): void
    {
        $entry = new Entry(new Dn('cn=other,dc=foo,dc=bar'));

        $this->inner
            ->expects(self::once())
            ->method('isEntryVisible')
            ->with(
                $this->user,
                $entry,
            )
            ->willReturn(false);

        self::assertFalse($this->subject->isEntryVisible(
            $this->user,
            $entry,
        ));
    }
}
