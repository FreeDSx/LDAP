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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Protocol\Factory\FilterFactory;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PHPUnit\Framework\TestCase;

final class FilterFactoryTest extends TestCase
{
    public function test_it_should_check_if_a_mapping_exists(): void
    {
        self::assertTrue(FilterFactory::has(0));
        self::assertFalse(FilterFactory::has(99));
    }

    public function test_it_should_set_a_mapping(): void
    {
        FilterFactory::set(99, EqualityFilter::class);

        self::assertTrue(FilterFactory::has(99));
    }

    public function test_it_should_get_a_mapping(): void
    {
        self::assertEquals(
            new EqualityFilter('foo', 'bar'),
            FilterFactory::get((new EqualityFilter('foo', 'bar'))->toAsn1())
        );
    }
}
