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

use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\Search\StorageListOptionsFactory;
use FreeDSx\Ldap\Server\SearchLimits;
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
}
