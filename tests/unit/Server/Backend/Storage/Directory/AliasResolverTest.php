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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Directory;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\AliasResolver;
use PHPUnit\Framework\TestCase;

final class AliasResolverTest extends TestCase
{
    private const BASE = 'dc=example,dc=com';

    public function test_a_name_that_is_no_alias_resolves_to_nothing(): void
    {
        $subject = $this->resolverFor([$this->target()]);

        self::assertNull($subject->resolve(new Dn('cn=target,' . self::BASE)));
    }

    public function test_an_absent_name_resolves_to_nothing(): void
    {
        $subject = $this->resolverFor([$this->target()]);

        self::assertNull($subject->resolve(new Dn('cn=nothere,' . self::BASE)));
    }

    public function test_an_alias_resolves_to_the_entry_it_names(): void
    {
        $subject = $this->resolverFor([
            $this->target(),
            $this->alias('ptr', 'cn=target,' . self::BASE),
        ]);

        self::assertSame(
            'cn=target,' . self::BASE,
            $subject->resolve(new Dn('cn=ptr,' . self::BASE))?->getDn()->toString(),
        );
    }

    public function test_an_alias_naming_another_alias_resolves_to_the_end_of_the_chain(): void
    {
        $subject = $this->resolverFor([
            $this->target(),
            $this->alias('one', 'cn=two,' . self::BASE),
            $this->alias('two', 'cn=target,' . self::BASE),
        ]);

        self::assertSame(
            'cn=target,' . self::BASE,
            $subject->resolve(new Dn('cn=one,' . self::BASE))?->getDn()->toString(),
        );
    }

    public function test_an_alias_naming_a_missing_entry_is_an_alias_problem(): void
    {
        $subject = $this->resolverFor([$this->alias('ptr', 'cn=gone,' . self::BASE)]);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ALIAS_PROBLEM);

        $subject->resolve(new Dn('cn=ptr,' . self::BASE));
    }

    public function test_an_alias_loop_is_an_alias_problem(): void
    {
        $subject = $this->resolverFor([
            $this->alias('one', 'cn=two,' . self::BASE),
            $this->alias('two', 'cn=one,' . self::BASE),
        ]);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ALIAS_PROBLEM);

        $subject->resolve(new Dn('cn=one,' . self::BASE));
    }

    public function test_an_alias_carrying_no_aliased_object_name_is_an_alias_problem(): void
    {
        $subject = $this->resolverFor([Entry::fromArray('cn=ptr,' . self::BASE, [
            'objectClass' => ['top', 'alias', 'extensibleObject'],
            'cn' => 'ptr',
        ])]);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ALIAS_PROBLEM);

        $subject->resolve(new Dn('cn=ptr,' . self::BASE));
    }

    public function test_an_alias_naming_something_that_is_not_a_dn_is_an_alias_problem(): void
    {
        $subject = $this->resolverFor([$this->alias('ptr', 'not a dn')]);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ALIAS_PROBLEM);

        $subject->resolve(new Dn('cn=ptr,' . self::BASE));
    }

    public function test_it_recognizes_an_alias_by_its_object_class_whatever_the_case(): void
    {
        $subject = $this->resolverFor([]);

        self::assertTrue($subject->isAlias(Entry::fromArray('cn=ptr,' . self::BASE, [
            'objectClass' => ['top', 'ALIAS'],
        ])));
        self::assertFalse($subject->isAlias(Entry::fromArray('cn=plain,' . self::BASE, [
            'objectClass' => ['top', 'person'],
        ])));
    }

    /**
     * @param list<Entry> $entries
     */
    private function resolverFor(array $entries): AliasResolver
    {
        return new AliasResolver(new InMemoryStorage([
            Entry::fromArray(self::BASE, ['objectClass' => ['top', 'domain'], 'dc' => 'example']),
            ...$entries,
        ]));
    }

    private function target(): Entry
    {
        return Entry::fromArray('cn=target,' . self::BASE, [
            'objectClass' => ['top', 'person'],
            'cn' => 'target',
            'sn' => 'Target',
        ]);
    }

    private function alias(
        string $name,
        string $target,
    ): Entry {
        return Entry::fromArray("cn=$name," . self::BASE, [
            'objectClass' => ['top', 'alias', 'extensibleObject'],
            'cn' => $name,
            'aliasedObjectName' => $target,
        ]);
    }
}
