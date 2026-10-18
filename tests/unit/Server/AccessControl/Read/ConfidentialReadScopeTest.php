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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl\Read;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\Read\ConfidentialReadScope;
use FreeDSx\Ldap\Server\AccessControl\Read\ReadScopeInterface;
use FreeDSx\Ldap\Server\AccessControl\Read\ReadVerdict;
use FreeDSx\Ldap\Server\AccessControl\WithheldAttributePolicy;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ConfidentialReadScopeTest extends TestCase
{
    private ReadScopeInterface&MockObject $inner;

    private AccessControlInterface&MockObject $accessControl;

    private BindToken $user;

    private Dn $dn;

    private ConfidentialReadScope $subject;

    protected function setUp(): void
    {
        $this->inner = $this->createMock(ReadScopeInterface::class);
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->user = BindToken::fromDn('cn=user,dc=foo,dc=bar');
        $this->dn = new Dn('cn=other,dc=foo,dc=bar');
        $this->subject = new ConfidentialReadScope(
            $this->inner,
            new WithheldAttributePolicy(
                $this->accessControl,
                SchemaResource::Core->load(),
            ),
            $this->user,
        );
    }

    public function test_a_deny_from_the_inner_scope_stays_a_deny_for_a_confidential_attribute(): void
    {
        $this->inner
            ->method('verdict')
            ->with('userpassword')
            ->willReturn(ReadVerdict::Deny);

        self::assertSame(
            ReadVerdict::Deny,
            $this->subject->verdict('userpassword'),
        );
    }

    public function test_a_confidential_attribute_the_inner_scope_allows_is_decided_on_each_entry(): void
    {
        $this->inner
            ->method('verdict')
            ->with('userpassword')
            ->willReturn(ReadVerdict::Allow);

        self::assertSame(
            ReadVerdict::PerEntry,
            $this->subject->verdict('userpassword'),
        );
    }

    public function test_an_attribute_that_is_not_confidential_keeps_the_inner_verdict(): void
    {
        $this->inner
            ->method('verdict')
            ->with('cn')
            ->willReturn(ReadVerdict::Allow);

        self::assertSame(
            ReadVerdict::Allow,
            $this->subject->verdict('cn'),
        );
    }

    public function test_a_grant_is_not_looked_for_when_the_inner_scope_withholds_the_attribute(): void
    {
        $this->inner
            ->method('isReadableOn')
            ->willReturn(false);
        $this->accessControl
            ->expects(self::never())
            ->method('hasConfidentialAccess');

        self::assertFalse($this->subject->isReadableOn(
            'userpassword',
            $this->dn,
        ));
    }

    public function test_a_confidential_attribute_is_withheld_without_a_grant(): void
    {
        $this->inner
            ->method('isReadableOn')
            ->willReturn(true);
        $this->accessControl
            ->expects(self::once())
            ->method('hasConfidentialAccess')
            ->with(
                $this->user,
                'userpassword',
            )
            ->willReturn(false);

        self::assertFalse($this->subject->isReadableOn(
            'userpassword',
            $this->dn,
        ));
    }

    public function test_a_confidential_attribute_is_readable_with_a_grant(): void
    {
        $this->inner
            ->method('isReadableOn')
            ->willReturn(true);
        $this->accessControl
            ->method('hasConfidentialAccess')
            ->willReturn(true);

        self::assertTrue($this->subject->isReadableOn(
            'userpassword',
            $this->dn,
        ));
    }

    public function test_an_attribute_that_is_not_confidential_is_readable_without_a_grant(): void
    {
        $this->inner
            ->method('isReadableOn')
            ->willReturn(true);
        $this->accessControl
            ->expects(self::never())
            ->method('hasConfidentialAccess');

        self::assertTrue($this->subject->isReadableOn(
            'cn',
            $this->dn,
        ));
    }

    public function test_readable_withholds_a_confidential_attribute_without_a_grant(): void
    {
        $this->inner
            ->method('isReadableOn')
            ->willReturn(true);
        $this->accessControl
            ->method('hasConfidentialAccess')
            ->willReturn(false);

        $readable = $this->subject->readable(new Entry(
            $this->dn,
            new Attribute(
                'cn',
                'other',
            ),
            new Attribute(
                'userPassword',
                'secret',
            ),
        ));

        self::assertNotNull($readable->get('cn'));
        self::assertNull($readable->get('userPassword'));
    }

    public function test_it_is_current_only_while_the_inner_scope_is(): void
    {
        $this->inner
            ->method('isCurrent')
            ->willReturn(false);

        self::assertFalse($this->subject->isCurrent());
    }

    public function test_entry_visibility_comes_from_the_inner_scope(): void
    {
        $entry = new Entry($this->dn);
        $this->inner
            ->method('isEntryVisible')
            ->with($entry)
            ->willReturn(false);

        self::assertFalse($this->subject->isEntryVisible($entry));
    }
}
