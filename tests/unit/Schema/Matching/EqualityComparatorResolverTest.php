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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Matching;

use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\ObjectIdentifierComparator;
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\SchemaResource;
use PHPUnit\Framework\TestCase;

final class EqualityComparatorResolverTest extends TestCase
{
    private CaseIgnoreComparator $default;

    private EqualityComparatorResolver $subject;

    protected function setUp(): void
    {
        $this->default = new CaseIgnoreComparator();
        $this->subject = new EqualityComparatorResolver(
            SchemaResource::Core->load(),
            $this->default,
        );
    }

    public function test_it_resolves_the_comparator_of_the_types_equality_rule(): void
    {
        self::assertInstanceOf(
            ObjectIdentifierComparator::class,
            $this->subject->for('objectClass'),
        );
    }

    public function test_it_resolves_the_same_comparator_however_the_type_is_spelled(): void
    {
        self::assertSame(
            $this->subject->for('objectClass'),
            $this->subject->for('OBJECTCLASS;x-tag'),
        );
    }

    public function test_an_undefined_type_falls_back_to_the_default(): void
    {
        self::assertSame(
            $this->default,
            $this->subject->for('undefinedType'),
        );
    }

    public function test_a_type_still_resolves_after_more_types_than_are_remembered(): void
    {
        self::assertInstanceOf(
            ObjectIdentifierComparator::class,
            $this->subject->for('objectClass'),
        );

        for ($i = 0; $i < 1100; $i++) {
            self::assertSame(
                $this->default,
                $this->subject->for("undefinedType{$i}"),
            );
        }

        self::assertInstanceOf(
            ObjectIdentifierComparator::class,
            $this->subject->for('objectClass'),
        );
    }
}
