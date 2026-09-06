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

namespace Tests\Unit\FreeDSx\Ldap\Server\Paging;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Paging\FillingPage;
use FreeDSx\Ldap\Server\Paging\SliceEnd;
use PHPUnit\Framework\TestCase;

final class FillingPageTest extends TestCase
{
    private FillingPage $subject;

    protected function setUp(): void
    {
        $this->subject = new FillingPage(
            pageLimit: 10,
            sizeLimit: 0,
            widestSlice: 1000,
        );
    }

    public function test_the_first_read_asks_only_for_what_the_page_can_hold(): void
    {
        self::assertSame(
            10,
            $this->subject->nextSlice(true, null)->limit,
        );
    }

    public function test_a_later_read_is_widened_by_what_a_match_has_cost_so_far(): void
    {
        $this->subject->nextSlice(true, null);
        $this->subject->readCandidates(100);
        $this->take(1);

        // Nine still wanted, at a hundred candidates per match.
        self::assertSame(
            900,
            $this->subject->nextSlice(true, null)->limit,
        );
    }

    public function test_a_later_read_is_never_wider_than_the_widest_slice(): void
    {
        $this->subject->nextSlice(true, null);
        $this->subject->readCandidates(5000);
        $this->take(1);

        self::assertSame(
            1000,
            $this->subject->nextSlice(true, null)->limit,
        );
    }

    public function test_a_later_read_takes_the_widest_slice_when_nothing_has_matched_yet(): void
    {
        $this->subject->nextSlice(true, null);
        $this->subject->readCandidates(50);

        self::assertSame(
            1000,
            $this->subject->nextSlice(true, null)->limit,
        );
    }

    public function test_a_read_that_only_probes_for_a_further_match_is_never_widened(): void
    {
        $this->subject->nextSlice(true, null);
        $this->subject->readCandidates(500);
        $this->take(10);

        self::assertSame(
            10,
            $this->subject->nextSlice(false, null)->limit,
        );
    }

    public function test_an_unbounded_page_reads_the_widest_slice(): void
    {
        $subject = new FillingPage(
            pageLimit: null,
            sizeLimit: 0,
            widestSlice: 250,
        );

        self::assertSame(
            250,
            $subject->nextSlice(true, null)->limit,
        );
        self::assertTrue($subject->hasCapacity());
    }

    public function test_an_entry_with_no_position_is_placed_while_the_read_is_not_widened(): void
    {
        $this->subject->nextSlice(true, null);

        self::assertTrue($this->subject->canPlace(null));
    }

    public function test_an_entry_with_no_position_is_refused_while_the_read_is_widened(): void
    {
        $this->subject->nextSlice(true, null);
        $this->subject->readCandidates(100);
        $this->take(1);
        $this->subject->nextSlice(true, null);

        self::assertFalse($this->subject->canPlace(null));
        self::assertTrue($this->subject->canPlace(PageCursor::afterEntry(7)));
    }

    public function test_a_read_that_could_not_place_an_entry_stops_the_page_widening_again(): void
    {
        $this->subject->nextSlice(true, null);
        $this->subject->readCandidates(100);
        $this->take(1);
        $this->subject->nextSlice(true, null);
        $this->subject->abandonSlice(SliceEnd::Unplaceable);

        // Back to asking only for the shortfall, which a read can always place.
        self::assertSame(
            9,
            $this->subject->nextSlice(true, null)->limit,
        );
        self::assertTrue($this->subject->canPlace(null));
    }

    public function test_filling_the_page_part_way_through_a_read_does_not_stop_it_widening(): void
    {
        $this->subject->nextSlice(true, null);
        $this->subject->readCandidates(100);
        $this->take(1);
        $this->subject->nextSlice(true, null);
        $this->subject->abandonSlice(SliceEnd::PageFull);

        self::assertSame(
            900,
            $this->subject->nextSlice(true, null)->limit,
        );
    }

    public function test_the_page_resumes_from_the_last_entry_it_placed(): void
    {
        $this->subject->add(
            Entry::create('cn=1,dc=foo,dc=bar'),
            PageCursor::afterEntry(4),
        );
        $this->subject->add(
            Entry::create('cn=2,dc=foo,dc=bar'),
            PageCursor::afterEntry(9),
        );

        self::assertEquals(
            PageCursor::afterEntry(9),
            $this->subject->nextSlice(true, null)->after,
        );
    }

    public function test_a_placed_entry_with_no_position_leaves_the_resume_point_alone(): void
    {
        $this->subject->add(
            Entry::create('cn=1,dc=foo,dc=bar'),
            PageCursor::afterEntry(4),
        );
        $this->subject->add(
            Entry::create('cn=2,dc=foo,dc=bar'),
            null,
        );

        self::assertEquals(
            PageCursor::afterEntry(4),
            $this->subject->nextSlice(true, null)->after,
        );
    }

    public function test_the_page_is_full_once_it_holds_its_limit(): void
    {
        $this->take(9);
        self::assertTrue($this->subject->hasCapacity());

        $this->take(1);
        self::assertFalse($this->subject->hasCapacity());
    }

    public function test_the_size_limit_is_only_reachable_once_the_page_holds_that_many(): void
    {
        $subject = new FillingPage(
            pageLimit: 10,
            sizeLimit: 2,
            widestSlice: 1000,
        );

        self::assertFalse($subject->mayExceedSizeLimit());

        $subject->add(Entry::create('cn=1,dc=foo,dc=bar'), null);
        $subject->add(Entry::create('cn=2,dc=foo,dc=bar'), null);

        self::assertTrue($subject->mayExceedSizeLimit());
    }

    public function test_it_collects_what_it_placed_with_where_it_stopped(): void
    {
        $this->subject->add(
            Entry::create('cn=1,dc=foo,dc=bar'),
            PageCursor::afterEntry(3),
        );

        $collected = $this->subject->collected(false, true);

        self::assertCount(
            1,
            $collected->entries,
        );
        self::assertFalse($collected->isResultExhausted);
        self::assertTrue($collected->isSizeLimitExceeded);
        self::assertEquals(
            PageCursor::afterEntry(3),
            $collected->cursor,
        );
    }

    private function take(int $count): void
    {
        for ($i = 0; $i < $count; $i++) {
            $this->subject->add(
                Entry::create("cn=$i,dc=foo,dc=bar"),
                PageCursor::afterEntry($i + 1),
            );
        }
    }
}
