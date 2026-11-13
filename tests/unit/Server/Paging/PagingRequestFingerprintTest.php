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

use FreeDSx\Ldap\Control\Ad\SdFlagsControl;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Control\SubentriesControl;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingRequestFingerprint;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PagingRequestFingerprintTest extends TestCase
{
    private PagingRequestFingerprint $subject;

    protected function setUp(): void
    {
        $this->subject = new PagingRequestFingerprint();
    }

    public function test_the_cookie_and_page_size_do_not_change_the_fingerprint(): void
    {
        self::assertSame(
            $this->subject->of($this->pagingRequest(control: new PagingControl(
                100,
                '',
            ))),
            $this->subject->of($this->pagingRequest(control: new PagingControl(
                50,
                'foo',
            ))),
        );
    }

    #[DataProvider('filtersSharingAStringProvider')]
    public function test_filters_sharing_a_string_form_are_told_apart(
        FilterInterface $first,
        FilterInterface $next,
    ): void {
        self::assertNotSame(
            $this->subject->of($this->pagingRequest(search: self::search()->setFilter($first))),
            $this->subject->of($this->pagingRequest(search: self::search()->setFilter($next))),
        );
    }

    /**
     * @return iterable<string, array{FilterInterface, FilterInterface}>
     */
    public static function filtersSharingAStringProvider(): iterable
    {
        yield 'an asterisk and its escape' => [
            Filters::equal(
                'cn',
                '*',
            ),
            Filters::equal(
                'cn',
                '\2a',
            ),
        ];
        yield 'a NUL and its escape' => [
            Filters::equal(
                'cn',
                "\x00",
            ),
            Filters::equal(
                'cn',
                '\00',
            ),
        ];
        yield 'presence and an empty initial substring' => [
            Filters::present('cn'),
            Filters::startsWith(
                'cn',
                '',
            ),
        ];
    }

    public function test_filters_without_a_string_form_are_told_apart(): void
    {
        self::assertNotSame(
            $this->subject->of($this->pagingRequest(search: self::search()->setFilter(Filters::equal(
                'bad_attr',
                'x',
            )))),
            $this->subject->of($this->pagingRequest(search: self::search()->setFilter(Filters::equal(
                'bad_attr',
                'y',
            )))),
        );
    }

    #[DataProvider('changedSearchProvider')]
    public function test_a_changed_search_changes_the_fingerprint(SearchRequest $changed): void
    {
        self::assertNotSame(
            $this->subject->of($this->pagingRequest()),
            $this->subject->of($this->pagingRequest(search: $changed)),
        );
    }

    /**
     * @return iterable<string, array{SearchRequest}>
     */
    public static function changedSearchProvider(): iterable
    {
        yield 'filter' => [
            self::search()->setFilter(new EqualityFilter(
                'cn',
                'bar',
            )),
        ];
        yield 'base DN' => [
            self::search()->base('dc=bar,dc=foo'),
        ];
        yield 'scope' => [
            self::search()->useSingleLevelScope(),
        ];
        yield 'alias dereferencing' => [
            self::search()->setDereferenceAliases(SearchRequest::DEREF_ALWAYS),
        ];
        yield 'size limit' => [
            self::search()->sizeLimit(5),
        ];
        yield 'time limit' => [
            self::search()->timeLimit(5),
        ];
        yield 'types only' => [
            self::search()->setAttributesOnly(true),
        ];
        yield 'attributes' => [
            self::search()->select(
                'cn',
                'sn',
            ),
        ];
        yield 'attribute options' => [
            self::search()->select('cn;lang-en'),
        ];
    }

    #[DataProvider('equivalentAttributesProvider')]
    public function test_equivalent_attributes_keep_the_fingerprint(
        SearchRequest $first,
        SearchRequest $next,
    ): void {
        self::assertSame(
            $this->subject->of($this->pagingRequest(search: $first)),
            $this->subject->of($this->pagingRequest(search: $next)),
        );
    }

    /**
     * @return iterable<string, array{SearchRequest, SearchRequest}>
     */
    public static function equivalentAttributesProvider(): iterable
    {
        yield 'order' => [
            self::search()->select(
                'cn',
                'sn',
            ),
            self::search()->select(
                'sn',
                'cn',
            ),
        ];
        yield 'name case' => [
            self::search()->select('cn'),
            self::search()->select('CN'),
        ];
        yield 'option order and case' => [
            self::search()->select('cn;lang-en;binary'),
            self::search()->select('cn;Binary;LANG-EN'),
        ];
    }

    public function test_the_paging_criticality_changes_the_fingerprint(): void
    {
        self::assertNotSame(
            $this->subject->of($this->pagingRequest()),
            $this->subject->of($this->pagingRequest(control: (new PagingControl(
                100,
                '',
            ))->setCriticality(true))),
        );
    }

    public function test_an_added_control_changes_the_fingerprint(): void
    {
        self::assertNotSame(
            $this->subject->of($this->pagingRequest()),
            $this->subject->of($this->pagingRequest(
                controls: new ControlBag(new SdFlagsControl(SdFlagsControl::DACL_SECURITY_INFORMATION)),
            )),
        );
    }

    public function test_a_control_value_changes_the_fingerprint(): void
    {
        self::assertNotSame(
            $this->subject->of($this->pagingRequest(
                controls: new ControlBag(new SdFlagsControl(SdFlagsControl::DACL_SECURITY_INFORMATION)),
            )),
            $this->subject->of($this->pagingRequest(
                controls: new ControlBag(new SdFlagsControl(SdFlagsControl::SACL_SECURITY_INFORMATION)),
            )),
        );
    }

    public function test_the_same_controls_in_another_order_keep_the_fingerprint(): void
    {
        self::assertSame(
            $this->subject->of($this->pagingRequest(controls: new ControlBag(
                new SdFlagsControl(SdFlagsControl::DACL_SECURITY_INFORMATION),
                new SubentriesControl(true),
            ))),
            $this->subject->of($this->pagingRequest(controls: new ControlBag(
                new SubentriesControl(true),
                new SdFlagsControl(SdFlagsControl::DACL_SECURITY_INFORMATION),
            ))),
        );
    }

    private function pagingRequest(
        ?SearchRequest $search = null,
        ?PagingControl $control = null,
        ?ControlBag $controls = null,
    ): PagingRequest {
        return new PagingRequest(
            $control ?? new PagingControl(
                100,
                '',
            ),
            $search ?? self::search(),
            $controls ?? new ControlBag(),
        );
    }

    private static function search(): SearchRequest
    {
        return (new SearchRequest(new EqualityFilter(
            'cn',
            'foo',
        )))
            ->base('dc=foo,dc=bar')
            ->select('cn');
    }
}
