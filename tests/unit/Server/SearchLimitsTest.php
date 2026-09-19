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

namespace Tests\Unit\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Server\SearchLimits;
use PHPUnit\Framework\TestCase;

final class SearchLimitsTest extends TestCase
{
    public function test_effective_paged_lookthrough_uses_the_paged_value_when_set(): void
    {
        $limits = new SearchLimits(
            maxSearchLookthrough: 5000,
            maxSearchPagedLookthrough: 100000,
        );

        self::assertSame(
            100000,
            $limits->effectivePagedLookthrough(),
        );
    }

    public function test_a_rule_naming_no_linked_value_limit_keeps_the_default_one(): void
    {
        $merged = (new SearchLimits(maxSearchSize: 10))->mergedOver(new SearchLimits(maxLinkedValues: 500));

        self::assertSame(
            500,
            $merged->maxLinkedValues(),
        );
    }

    public function test_a_rule_naming_a_linked_value_limit_overrides_the_default_one(): void
    {
        $merged = (new SearchLimits(maxLinkedValues: 0))->mergedOver(new SearchLimits(maxLinkedValues: 500));

        self::assertSame(
            0,
            $merged->maxLinkedValues(),
        );
    }

    public function test_effective_paged_lookthrough_falls_back_to_the_regular_value(): void
    {
        $limits = new SearchLimits(
            maxSearchLookthrough: 5000,
            maxSearchPagedLookthrough: 0,
        );

        self::assertSame(
            5000,
            $limits->effectivePagedLookthrough(),
        );
    }
}
