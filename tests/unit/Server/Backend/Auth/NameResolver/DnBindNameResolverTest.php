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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Auth\NameResolver;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\DnBindNameResolver;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class DnBindNameResolverTest extends TestCase
{
    private LdapBackendInterface&MockObject $mockBackend;

    protected function setUp(): void
    {
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
    }

    public function test_resolve_calls_backend_get_with_dn(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('get')
            ->with(new Dn('cn=Alice,dc=example,dc=com'))
            ->willReturn($entry);

        $subject = new DnBindNameResolver();
        $result = $subject->resolve(
            'cn=Alice,dc=example,dc=com',
            $this->mockBackend
        );

        self::assertSame(
            $entry,
            $result
        );
    }

    public function test_resolve_returns_null_when_entry_not_found(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn(null);

        $subject = new DnBindNameResolver();
        $result = $subject->resolve('cn=Unknown,dc=example,dc=com', $this->mockBackend);

        self::assertNull($result);
    }
}
