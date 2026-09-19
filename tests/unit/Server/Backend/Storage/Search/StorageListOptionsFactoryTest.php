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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Search;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageSlice;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\Search\StorageListOptionsFactory;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class StorageListOptionsFactoryTest extends TestCase
{
    use ServerContainerTrait;

    private StorageListOptionsFactory $subject;

    private SearchRequest $request;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(StorageListOptionsFactory::class);
        $this->request = new SearchRequest(Filters::present('objectClass'));
    }

    public function test_limits_naming_no_linked_value_cap_read_to_the_default_one(): void
    {
        self::assertSame(
            EntryProjection::DEFAULT_LINK_CAP,
            $this->subject->projectionFor(
                $this->request,
                new SearchLimits(),
            )->linkCap,
        );
    }

    public function test_a_linked_value_cap_of_zero_reads_every_value(): void
    {
        self::assertNull(
            $this->subject->projectionFor(
                $this->request,
                new SearchLimits(maxLinkedValues: 0),
            )->linkCap,
        );
    }

    public function test_a_named_linked_value_cap_bounds_the_read(): void
    {
        self::assertSame(
            250,
            $this->subject->projectionFor(
                $this->request,
                new SearchLimits(maxLinkedValues: 250),
            )->linkCap,
        );
    }

    public function test_the_projection_materializes_what_the_request_names_and_its_filter_reads(): void
    {
        $request = (new SearchRequest(Filters::equal('sn', 'x')))->setAttributes('cn');

        self::assertEqualsCanonicalizing(
            [
                'cn',
                'commonname',
                'sn',
            ],
            $this->subject->projectionFor($request)->attributes,
        );
    }

    public function test_the_projection_asks_for_has_subordinates_when_the_request_names_it(): void
    {
        $request = $this->request->setAttributes('hasSubordinates');

        self::assertTrue($this->subject->projectionFor($request)->withHasSubordinates);
    }

    public function test_the_projection_does_not_ask_for_has_subordinates_when_the_request_omits_it(): void
    {
        self::assertFalse($this->subject->projectionFor($this->request)->withHasSubordinates);
    }

    public function test_the_scope_carries_the_base_depth_and_subentry_visibility(): void
    {
        $scope = $this->make(
            $this->request->useSubtreeScope(),
            subentries: SubentryVisibility::Hide,
        )->scope;

        self::assertSame(
            'dc=foo,dc=bar',
            $scope->baseDn->toString(),
        );
        self::assertTrue($scope->subtree);
        self::assertSame(
            SubentryVisibility::Hide,
            $scope->subentries,
        );
    }

    public function test_a_slice_deadline_bounds_the_read_over_the_time_limit(): void
    {
        $deadline = microtime(true) + 5.0;

        self::assertSame(
            $deadline,
            $this->make(
                $this->request->timeLimit(60),
                slice: new PageSlice(
                    limit: 10,
                    deadline: $deadline,
                ),
            )->bounds->deadline,
        );
    }

    public function test_a_slice_without_a_deadline_falls_back_to_the_time_limit(): void
    {
        $before = microtime(true);
        $deadline = $this->make(
            $this->request->timeLimit(60),
            slice: new PageSlice(limit: 10),
        )->bounds->deadline;

        self::assertNotNull($deadline);
        self::assertGreaterThanOrEqual(
            $before + 60,
            $deadline,
        );
    }

    public function test_the_bounds_carry_the_lookthrough_limit_and_slice(): void
    {
        $bounds = $this->make(
            $this->request,
            limits: new SearchLimits(maxSearchLookthrough: 42),
            slice: new PageSlice(limit: 7),
        )->bounds;

        self::assertSame(
            42,
            $bounds->lookthroughLimit,
        );
        self::assertSame(
            7,
            $bounds->limit(),
        );
    }

    private function make(
        SearchRequest $request,
        SubentryVisibility $subentries = SubentryVisibility::All,
        ?SearchLimits $limits = null,
        ?PageSlice $slice = null,
    ): StorageListOptions {
        return $this->subject->make(
            $request,
            new Dn('dc=foo,dc=bar'),
            new ControlBag(),
            $subentries,
            $limits,
            $slice,
        );
    }
}
