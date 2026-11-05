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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\LinkKeys;
use PHPUnit\Framework\TestCase;

use function array_fill;
use function array_merge;
use function implode;
use function range;

final class LinkKeysTest extends TestCase
{
    public function test_a_span_is_read_between_its_first_and_last_id(): void
    {
        $keys = LinkKeys::span(
            3,
            9,
        );

        self::assertSame(
            'id BETWEEN ? AND ?',
            $keys->condition('id'),
        );
        self::assertSame(
            [3, 9],
            $keys->params(),
        );
    }

    public function test_a_single_id_is_read_as_a_span(): void
    {
        self::assertSame(
            [7, 7],
            LinkKeys::covering([7])->params(),
        );
    }

    public function test_ids_close_together_are_read_as_their_span(): void
    {
        $keys = LinkKeys::covering([5, 3, 8, 6]);

        self::assertSame(
            'id BETWEEN ? AND ?',
            $keys->condition('id'),
        );
        self::assertSame(
            [3, 8],
            $keys->params(),
        );
    }

    public function test_scattered_ids_are_read_by_the_ids_themselves(): void
    {
        $keys = LinkKeys::covering([1, 40, 90]);

        self::assertSame(
            'id IN (' . $this->markers(16) . ')',
            $keys->condition('id'),
        );
        self::assertSame(
            array_merge(
                [1, 40],
                array_fill(
                    0,
                    14,
                    90,
                ),
            ),
            $keys->params(),
        );
    }

    public function test_more_scattered_ids_than_the_short_list_holds_are_padded_to_the_long_one(): void
    {
        $ids = range(
            10,
            170,
            10,
        );
        $keys = LinkKeys::covering($ids);

        self::assertSame(
            'id IN (' . $this->markers(100) . ')',
            $keys->condition('id'),
        );
        self::assertSame(
            array_merge(
                $ids,
                array_fill(
                    0,
                    83,
                    170,
                ),
            ),
            $keys->params(),
        );
    }

    private function markers(int $count): string
    {
        return implode(
            ', ',
            array_fill(
                0,
                $count,
                '?',
            ),
        );
    }
}
