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
use FreeDSx\Ldap\Schema\AttributeTypeSpelling;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\DnBindNameResolver;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class DnBindNameResolverTest extends TestCase
{
    private ReadBackendInterface&MockObject $mockBackend;

    private DnBindNameResolver $subject;

    protected function setUp(): void
    {
        $this->mockBackend = $this->createMock(ReadBackendInterface::class);
        $this->subject = new DnBindNameResolver(new AttributeTypeSpelling(SchemaResource::Core->load()));
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
            ->with(self::callback(static fn(Dn $dn): bool => $dn->toString() === 'cn=Alice,dc=example,dc=com'))
            ->willReturn($entry);

        $result = $this->subject->resolve(
            'cn=Alice,dc=example,dc=com',
            $this->mockBackend,
        );

        self::assertSame(
            $entry,
            $result,
        );
    }

    public function test_resolve_looks_up_a_name_spelled_with_an_alias_by_its_primary_names(): void
    {
        $this->mockBackend
            ->expects(self::once())
            ->method('get')
            ->with(self::callback(static fn(Dn $dn): bool => $dn->toString() === 'cn=Alice,dc=example,dc=com'))
            ->willReturn(null);

        $this->subject->resolve(
            'commonName=Alice,dc=example,dc=com',
            $this->mockBackend,
        );
    }

    public function test_resolve_returns_null_when_entry_not_found(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn(null);

        $result = $this->subject->resolve(
            'cn=Unknown,dc=example,dc=com',
            $this->mockBackend,
        );

        self::assertNull($result);
    }
}
