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

namespace Tests\Unit\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Paging;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Unit\FreeDSx\Ldap\TestFactoryTrait;

final class PagingTest extends TestCase
{
    use TestFactoryTrait;

    private Paging $subject;

    private LdapClient&MockObject $client;

    private SearchRequest&MockObject $search;

    protected function setUp(): void
    {
        $this->client = $this->createMock(LdapClient::class);
        $this->search = $this->createMock(SearchRequest::class);

        $this->subject = new Paging(
            $this->client,
            $this->search,
            1000
        );
    }

    public function test_it_should_check_whether_paging_has_entries_left_and_return_true_on_start(): void
    {
        self::assertTrue($this->subject->hasEntries());
    }

    public function test_it_should_return_true_for_entries_when_the_cookie_is_not_empty(): void
    {
        $this->expectPagingControl(
            new PagingControl(1000, ''),
            self::makeSearchResponseFromEntries(
                entries: new Entries(
                    Entry::create('foo'),
                    Entry::create('bar'),
                ),
                controls: [new PagingControl(100, 'foo')],
            )
        );
        $this->subject->getEntries();

        self::assertTrue($this->subject->hasEntries());
    }

    public function test_it_should_return_false_for_entries_when_the_cookie_is_empty(): void
    {
        $this->expectPagingControl(
            new PagingControl(100, ''),
            self::makeSearchResponseFromEntries(
                controls: [new PagingControl(0, '')]
            )
        );

        $this->subject->getEntries(100);

        self::assertFalse($this->subject->hasEntries());
    }

    public function test_it_should_abort_a_paging_operation_if_end_is_called(): void
    {
        $this->client
            ->expects($this->atMost(2))
            ->method('sendAndReceive')
            ->with($this->search, $this->anything())
            ->will($this->onConsecutiveCalls(
                self::makeSearchResponseFromEntries(
                    controls: [new PagingControl(100, 'foo')]
                ),
                self::makeSearchResponseFromEntries(),
            ));

        $this->subject->getEntries();
        $this->subject->end();

        self::assertFalse($this->subject->hasEntries());
    }

    public function test_it_should_get_the_size_estimate_from_the_server_response(): void
    {
        $this->expectPagingControl(
            new PagingControl(1000, ''),
            self::makeSearchResponseFromEntries(
                entries: new Entries(
                    Entry::create('foo'),
                    Entry::create('bar'),
                ),
                controls: [new PagingControl(100, 'foo')],
            )
        );

        self::assertNull($this->subject->sizeEstimate());

        $this->subject->getEntries();

        self::assertSame(
            100,
            $this->subject->sizeEstimate()
        );
    }

    public function test_it_should_get_the_entries_from_the_response(): void
    {
        $this->expectPagingControl(
            new PagingControl(1000, ''),
            self::makeSearchResponseFromEntries(
                entries: new Entries(
                    Entry::create('foo'),
                    Entry::create('bar'),
                ),
                controls: [new PagingControl(100, 'foo')],
            )
        );

        self::assertEquals(
            new Entries(Entry::create('foo'), Entry::create('bar')),
            $this->subject->getEntries(),
        );
    }

    public function test_it_should_get_marked_as_ended_if_not_critical_and_no_control_is_returned(): void
    {
        $this->expectPagingControl(
            (new PagingControl(1000, ''))->setCriticality(false),
            self::makeSearchResponseFromEntries(
                entries: new Entries(
                    Entry::create('foo'),
                    Entry::create('bar')
                ),
            )
        );

        self::assertEquals(
            new Entries(Entry::create('foo'), Entry::create('bar')),
            $this->subject->getEntries(),
        );
        self::assertFalse($this->subject->hasEntries());
    }


    public function test_it_should_throw_an_exception_if_marked_as_critical_and_no_control_is_received(): void
    {
        self::expectException(ProtocolException::class);
        self::expectExceptionMessage('Expected a paging control, but received none.');

        $this->expectPagingControl(
            (new PagingControl(1000, ''))->setCriticality(true),
            self::makeSearchResponseFromEntries(
                entries: new Entries(
                    Entry::create('foo'),
                    Entry::create('bar')
                ),
            )
        );

        $this->subject->isCritical();
        $this->subject->getEntries();
    }

    private function expectPagingControl(
        PagingControl $control,
        ?LdapMessageResponse $response = null,
    ): void {
        $response ??= $this::makeSearchResponseFromEntries(
            controls: [new PagingControl(0, 'foo')]
        );

        $this->client
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with($this->search, $this->equalTo($control))
            ->willReturn($response);
    }
}
