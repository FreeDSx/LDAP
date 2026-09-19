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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Search\Options;

use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageSlice;
use FreeDSx\Ldap\Server\Backend\Storage\Search\Options\ReadBounds;
use PHPUnit\Framework\TestCase;

final class ReadBoundsTest extends TestCase
{
    public function test_without_a_slice_the_read_is_unbounded_and_starts_from_the_beginning(): void
    {
        $subject = new ReadBounds();

        self::assertNull($subject->limit());
        self::assertNull($subject->resumeAfter());
    }

    public function test_a_slice_bounds_the_read_and_names_where_it_resumes(): void
    {
        $cursor = PageCursor::afterEntry(12);
        $subject = new ReadBounds(slice: new PageSlice(
            limit: 5,
            after: $cursor,
        ));

        self::assertSame(
            5,
            $subject->limit(),
        );
        self::assertSame(
            $cursor,
            $subject->resumeAfter(),
        );
    }
}
