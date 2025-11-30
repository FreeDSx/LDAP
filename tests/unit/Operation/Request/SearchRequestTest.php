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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Search\Result\ReferralResult;
use PHPUnit\Framework\TestCase;

final class SearchRequestTest extends TestCase
{
    private SearchRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new SearchRequest(new EqualityFilter('cn', 'foo'));
    }

    public function test_it_should_set_the_attributes(): void
    {
        $this->subject->setAttributes(new Attribute('foo'));

        self::assertEquals(
            [new Attribute('foo')],
            $this->subject->getAttributes(),
        );
    }

    public function test_it_should_set_the_attributes_using_simple_string_values(): void
    {
        $this->subject->setAttributes('foo', 'bar');

        self::assertEquals(
            [new Attribute('foo'), new Attribute('bar')],
            $this->subject->getAttributes(),
        );
    }

    public function test_it_should_set_the_base_dn(): void
    {
        self::assertNull($this->subject->getBaseDn());

        $this->subject->setBaseDn('dc=foo');

        self::assertEquals(
            new Dn('dc=foo'),
            $this->subject->getBaseDn(),
        );
    }

    public function test_it_should_set_the_scope(): void
    {
        self::assertEquals(
            SearchRequest::SCOPE_WHOLE_SUBTREE,
            $this->subject->getScope()
        );

        $this->subject->setScope(SearchRequest::SCOPE_BASE_OBJECT);

        self::assertEquals(
            SearchRequest::SCOPE_BASE_OBJECT,
            $this->subject->getScope()
        );
    }

    public function test_it_should_set_whether_or_not_to_dereference_aliases(): void
    {
        self::assertSame(
            SearchRequest::DEREF_NEVER,
            $this->subject->getDereferenceAliases(),
        );

        $this->subject->setDereferenceAliases(SearchRequest::DEREF_ALWAYS);

        self::assertSame(
            SearchRequest::DEREF_ALWAYS,
            $this->subject->getDereferenceAliases(),
        );
    }

    public function test_it_should_set_a_size_limit(): void
    {
        self::assertSame(
            0,
            $this->subject->getSizeLimit()
        );

        $this->subject->setSizeLimit(100);

        self::assertSame(
            100,
            $this->subject->getSizeLimit(),
        );
    }

    public function test_it_should_set_a_time_limit(): void
    {
        self::assertSame(
            0,
            $this->subject->getTimeLimit(),
        );

        $this->subject->setTimeLimit(100);

        self::assertSame(
            100,
            $this->subject->getTimeLimit(),
        );
    }

    public function test_it_should_set_whether_or_not_to_get_attributes_only(): void
    {
        self::assertFalse($this->subject->getAttributesOnly());

        $this->subject->setAttributesOnly(true);

        self::assertTrue($this->subject->getAttributesOnly());
    }

    public function test_it_should_have_an_alias_for_set_attributes_called_select(): void
    {
        $this->subject->select('foo', 'bar');

        self::assertEquals(
            [new Attribute('foo'), new Attribute('bar')],
            $this->subject->getAttributes(),
        );
    }

    public function test_it_should_have_an_alias_for_setBaseDn_called_base(): void
    {
        $this->subject->base('dc=foo');

        self::assertEquals(
            new Dn('dc=foo'),
            $this->subject->getBaseDn(),
        );
    }

    public function test_it_should_have_a_method_to_set_the_scopes(): void
    {
        $this->subject->useBaseScope();
        self::assertSame(
            SearchRequest::SCOPE_BASE_OBJECT,
            $this->subject->getScope(),
        );

        $this->subject->useSubtreeScope();
        self::assertSame(
            SearchRequest::SCOPE_WHOLE_SUBTREE,
            $this->subject->getScope(),
        );

        $this->subject->useSingleLevelScope();
        self::assertSame(
            SearchRequest::SCOPE_SINGLE_LEVEL,
            $this->subject->getScope(),
        );
    }

    public function test_it_should_set_and_get_an_entry_handler(): void
    {
        $handler = fn (EntryResult $result) => $result->getEntry();

        $this->subject->useEntryHandler($handler);

        self::assertSame(
            $handler,
            $this->subject->getEntryHandler(),
        );
    }

    public function test_it_should_set_and_get_a_referral_handler(): void
    {
        $handler = fn (ReferralResult $result) => $result->getReferrals();

        $this->subject->useReferralHandler($handler);

        self::assertSame(
            $handler,
            $this->subject->getReferralHandler(),
        );
    }

    public function test_it_should_set_and_get_the_cancel_strategy(): void
    {
        $this->subject->useCancelStrategy(SearchRequest::CANCEL_CONTINUE);

        self::assertSame(
            SearchRequest::CANCEL_CONTINUE,
            $this->subject->getCancelStrategy(),
        );
    }

    public function test_it_should_not_allow_invalid_cancel_stragegies(): void
    {
        $this->expectException(UnexpectedValueException::class);

        $this->subject->useCancelStrategy('foo');
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $this->subject->setBaseDn('dc=foo,dc=bar');

        self::assertEquals(
            Asn1::application(3, Asn1::sequence(
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::enumerated(2),
                Asn1::enumerated(0),
                Asn1::integer(0),
                Asn1::integer(0),
                Asn1::boolean(false),
                (new EqualityFilter('cn', 'foo'))->toAsn1(),
                Asn1::sequenceOf()
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $search = (new SearchRequest(new EqualityFilter('foo', 'bar'), 'cn'))
            ->base('dc,=foo,dc=bar')
            ->timeLimit(10)
            ->sizeLimit(5)
            ->useBaseScope()
            ->setAttributesOnly(true)
            ->setDereferenceAliases(2);

        $this->subject = SearchRequest::fromAsn1($search->toAsn1());

        self::assertEquals(
            new Dn('dc,=foo,dc=bar'),
            $this->subject->getBaseDn(),
        );
        self::assertSame(
            5,
            $this->subject->getSizeLimit(),
        );
        self::assertSame(
            10,
            $this->subject->getTimeLimit(),
        );
        self::assertSame(
            SearchRequest::SCOPE_BASE_OBJECT,
            $this->subject->getScope(),
        );
        self::assertTrue($this->subject->getAttributesOnly());
        self::assertSame(
            2,
            $this->subject->getDereferenceAliases(),
        );
    }

    /**
     * @dataProvider malformedAsn1DataProvider
     */
    public function test_it_should_not_be_constructed_from_invalid_asn1(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);

        SearchRequest::fromAsn1($type);
    }

    /**
     * @return array<array<AbstractType>>
     */
    public static function malformedAsn1DataProvider(): array
    {
        return [
            [Asn1::set()],
            [Asn1::sequence()],
            [Asn1::sequence(
                Asn1::integer(5),
                Asn1::octetString('foo')
            )],
        ];
    }
}
