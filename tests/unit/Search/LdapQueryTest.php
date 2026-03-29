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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\LdapQuery;
use FreeDSx\Ldap\Search\Paging;
use FreeDSx\Ldap\Search\Result\EntryResult;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class LdapQueryTest extends TestCase
{
    private LdapClient&MockObject $client;

    private LdapQuery $subject;

    protected function setUp(): void
    {
        $this->client = $this->createMock(LdapClient::class);
        $this->subject = new LdapQuery($this->client);
    }

    // -------------------------------------------------------------------------
    // toSearchRequest
    // -------------------------------------------------------------------------

    public function test_to_search_request_uses_present_objectClass_filter_by_default(): void
    {
        $request = $this->subject->toSearchRequest();

        self::assertEquals(
            new PresentFilter('objectClass'),
            $request->getFilter(),
        );
    }

    public function test_to_search_request_uses_whole_subtree_scope_by_default(): void
    {
        $request = $this->subject->toSearchRequest();

        self::assertSame(SearchRequest::SCOPE_WHOLE_SUBTREE, $request->getScope());
    }

    public function test_to_search_request_sets_base_dn(): void
    {
        $request = $this->subject
            ->from('dc=example,dc=local')
            ->toSearchRequest();

        self::assertEquals(new Dn('dc=example,dc=local'), $request->getBaseDn());
    }

    public function test_to_search_request_sets_base_dn_from_dn_object(): void
    {
        $request = $this->subject
            ->from(new Dn('dc=example,dc=local'))
            ->toSearchRequest();

        self::assertEquals(new Dn('dc=example,dc=local'), $request->getBaseDn());
    }

    public function test_to_search_request_base_dn_is_null_when_not_set(): void
    {
        $request = $this->subject->toSearchRequest();

        self::assertNull($request->getBaseDn());
    }

    public function test_to_search_request_sets_subtree_scope(): void
    {
        $request = $this->subject
            ->useSubtreeScope()
            ->toSearchRequest();

        self::assertSame(SearchRequest::SCOPE_WHOLE_SUBTREE, $request->getScope());
    }

    public function test_to_search_request_sets_single_level_scope(): void
    {
        $request = $this->subject
            ->useSingleLevelScope()
            ->toSearchRequest();

        self::assertSame(SearchRequest::SCOPE_SINGLE_LEVEL, $request->getScope());
    }

    public function test_to_search_request_sets_base_scope(): void
    {
        $request = $this->subject
            ->useBaseScope()
            ->toSearchRequest();

        self::assertSame(SearchRequest::SCOPE_BASE_OBJECT, $request->getScope());
    }

    public function test_to_search_request_sets_attributes_from_strings(): void
    {
        $request = $this->subject
            ->select('cn', 'mail')
            ->toSearchRequest();

        self::assertEquals(
            [new Attribute('cn'), new Attribute('mail')],
            $request->getAttributes(),
        );
    }

    public function test_to_search_request_sets_attributes_from_attribute_objects(): void
    {
        $cn = new Attribute('cn');
        $mail = new Attribute('mail');

        $request = $this->subject
            ->select($cn, $mail)
            ->toSearchRequest();

        self::assertEquals([$cn, $mail], $request->getAttributes());
    }

    public function test_to_search_request_sets_size_limit(): void
    {
        $request = $this->subject
            ->sizeLimit(50)
            ->toSearchRequest();

        self::assertSame(50, $request->getSizeLimit());
    }

    public function test_to_search_request_does_not_set_size_limit_when_not_configured(): void
    {
        $request = $this->subject->toSearchRequest();

        self::assertSame(0, $request->getSizeLimit());
    }

    public function test_to_search_request_sets_time_limit(): void
    {
        $request = $this->subject
            ->timeLimit(30)
            ->toSearchRequest();

        self::assertSame(30, $request->getTimeLimit());
    }

    public function test_to_search_request_does_not_set_time_limit_when_not_configured(): void
    {
        $request = $this->subject->toSearchRequest();

        self::assertSame(0, $request->getTimeLimit());
    }

    // -------------------------------------------------------------------------
    // where / andWhere / orWhere
    // -------------------------------------------------------------------------

    public function test_where_replaces_the_filter(): void
    {
        $filter = Filters::equal('cn', 'foo');

        $request = $this->subject
            ->where($filter)
            ->toSearchRequest();

        self::assertSame($filter, $request->getFilter());
    }

    public function test_where_replaces_an_existing_filter(): void
    {
        $original = Filters::equal('cn', 'foo');
        $replacement = Filters::equal('sn', 'bar');

        $request = $this->subject
            ->where($original)
            ->where($replacement)
            ->toSearchRequest();

        self::assertSame($replacement, $request->getFilter());
    }

    public function test_and_where_sets_filter_directly_on_first_call(): void
    {
        $filter = Filters::equal('cn', 'foo');

        $request = $this->subject
            ->andWhere($filter)
            ->toSearchRequest();

        self::assertSame($filter, $request->getFilter());
    }

    public function test_and_where_wraps_in_and_filter_on_second_call(): void
    {
        $first = Filters::equal('objectClass', 'user');
        $second = Filters::present('telephoneNumber');

        $request = $this->subject
            ->andWhere($first)
            ->andWhere($second)
            ->toSearchRequest();

        $filter = $request->getFilter();
        self::assertInstanceOf(AndFilter::class, $filter);
        self::assertSame([$first, $second], $filter->get());
    }

    public function test_and_where_appends_to_existing_and_filter(): void
    {
        $first = Filters::equal('objectClass', 'user');
        $second = Filters::present('telephoneNumber');
        $third = Filters::startsWith('cn', 'A');

        $request = $this->subject
            ->andWhere($first)
            ->andWhere($second)
            ->andWhere($third)
            ->toSearchRequest();

        $filter = $request->getFilter();
        self::assertInstanceOf(AndFilter::class, $filter);
        self::assertSame([$first, $second, $third], $filter->get());
    }

    public function test_and_where_wraps_non_and_filter_in_and(): void
    {
        $existing = Filters::or(
            Filters::equal('objectClass', 'user'),
            Filters::equal('objectClass', 'group'),
        );
        $additional = Filters::present('cn');

        $request = $this->subject
            ->where($existing)
            ->andWhere($additional)
            ->toSearchRequest();

        $filter = $request->getFilter();
        self::assertInstanceOf(AndFilter::class, $filter);
        self::assertSame([$existing, $additional], $filter->get());
    }

    public function test_or_where_sets_filter_directly_on_first_call(): void
    {
        $filter = Filters::equal('cn', 'foo');

        $request = $this->subject
            ->orWhere($filter)
            ->toSearchRequest();

        self::assertSame($filter, $request->getFilter());
    }

    public function test_or_where_wraps_in_or_filter_on_second_call(): void
    {
        $first = Filters::equal('objectClass', 'user');
        $second = Filters::equal('objectClass', 'group');

        $request = $this->subject
            ->orWhere($first)
            ->orWhere($second)
            ->toSearchRequest();

        $filter = $request->getFilter();
        self::assertInstanceOf(OrFilter::class, $filter);
        self::assertSame([$first, $second], $filter->get());
    }

    public function test_or_where_appends_to_existing_or_filter(): void
    {
        $first = Filters::equal('objectClass', 'user');
        $second = Filters::equal('objectClass', 'group');
        $third = Filters::equal('objectClass', 'contact');

        $request = $this->subject
            ->orWhere($first)
            ->orWhere($second)
            ->orWhere($third)
            ->toSearchRequest();

        $filter = $request->getFilter();
        self::assertInstanceOf(OrFilter::class, $filter);
        self::assertSame([$first, $second, $third], $filter->get());
    }

    public function test_or_where_wraps_non_or_filter_in_or(): void
    {
        $existing = new EqualityFilter('objectClass', 'user');
        $additional = new EqualityFilter('objectClass', 'group');

        $request = $this->subject
            ->where($existing)
            ->orWhere($additional)
            ->toSearchRequest();

        $filter = $request->getFilter();
        self::assertInstanceOf(OrFilter::class, $filter);
        self::assertSame([$existing, $additional], $filter->get());
    }

    // -------------------------------------------------------------------------
    // get
    // -------------------------------------------------------------------------

    public function test_get_delegates_to_client_search(): void
    {
        $expected = new Entries(Entry::create('cn=foo,dc=example,dc=local'));

        $this->client
            ->expects(self::once())
            ->method('search')
            ->willReturn($expected);

        $result = $this->subject
            ->from('dc=example,dc=local')
            ->andWhere(Filters::equal('objectClass', 'user'))
            ->get();

        self::assertSame($expected, $result);
    }

    // -------------------------------------------------------------------------
    // first
    // -------------------------------------------------------------------------

    public function test_first_returns_the_first_entry(): void
    {
        $entry = Entry::create('cn=foo,dc=example,dc=local');

        $this->client
            ->method('search')
            ->willReturn(new Entries($entry));

        $result = $this->subject
            ->andWhere(Filters::equal('cn', 'foo'))
            ->first();

        self::assertSame($entry, $result);
    }

    public function test_first_returns_null_when_no_entries_found(): void
    {
        $this->client
            ->method('search')
            ->willReturn(new Entries());

        $result = $this->subject
            ->andWhere(Filters::equal('cn', 'nobody'))
            ->first();

        self::assertNull($result);
    }

    public function test_first_sets_size_limit_to_one_when_not_configured(): void
    {
        $this->client
            ->expects(self::once())
            ->method('search')
            ->with(self::callback(
                fn (SearchRequest $r) => $r->getSizeLimit() === 1
            ))
            ->willReturn(new Entries());

        $this->subject->first();
    }

    public function test_first_does_not_override_an_explicitly_configured_size_limit(): void
    {
        $this->client
            ->expects(self::once())
            ->method('search')
            ->with(self::callback(
                fn (SearchRequest $r) => $r->getSizeLimit() === 10
            ))
            ->willReturn(new Entries());

        $this->subject->sizeLimit(10)->first();
    }

    // -------------------------------------------------------------------------
    // paging
    // -------------------------------------------------------------------------

    public function test_paging_delegates_to_client_paging(): void
    {
        $paging = $this->createMock(Paging::class);

        $this->client
            ->expects(self::once())
            ->method('paging')
            ->with(
                self::isInstanceOf(SearchRequest::class),
                100,
            )
            ->willReturn($paging);

        $result = $this->subject->paging(100);

        self::assertSame($paging, $result);
    }

    public function test_paging_passes_null_page_size_by_default(): void
    {
        $paging = $this->createMock(Paging::class);

        $this->client
            ->expects(self::once())
            ->method('paging')
            ->with(
                self::isInstanceOf(SearchRequest::class),
                null,
            )
            ->willReturn($paging);

        $this->subject->paging();
    }

    // -------------------------------------------------------------------------
    // stream
    // -------------------------------------------------------------------------

    public function test_stream_yields_entry_results(): void
    {
        $result1 = new EntryResult(new LdapMessageResponse(
            1,
            new SearchResultEntry(Entry::create('cn=foo,dc=example,dc=local')),
        ));
        $result2 = new EntryResult(new LdapMessageResponse(
            1,
            new SearchResultEntry(Entry::create('cn=bar,dc=example,dc=local')),
        ));

        $this->client
            ->method('search')
            ->willReturnCallback(function (SearchRequest $request) use ($result1, $result2): Entries {
                $handler = $request->getEntryHandler();
                self::assertNotNull($handler);
                $handler($result1);
                $handler($result2);

                return new Entries();
            });

        $results = iterator_to_array(
            $this->subject
                ->andWhere(Filters::equal('objectClass', 'user'))
                ->stream()
        );

        self::assertSame([$result1, $result2], $results);
    }

    public function test_stream_yields_nothing_when_no_entries_found(): void
    {
        $this->client
            ->method('search')
            ->willReturn(new Entries());

        $results = iterator_to_array($this->subject->stream());

        self::assertSame([], $results);
    }

    public function test_stream_passes_controls_to_search(): void
    {
        $control = $this->createMock(\FreeDSx\Ldap\Control\Control::class);

        $this->client
            ->expects(self::once())
            ->method('search')
            ->with(
                self::isInstanceOf(SearchRequest::class),
                $control,
            )
            ->willReturn(new Entries());

        iterator_to_array($this->subject->stream($control));
    }
}
