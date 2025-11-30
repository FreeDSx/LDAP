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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Search\RangeRetrieval;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class RangeRetrievalTest extends TestCase
{
    private RangeRetrieval $subject;

    private LdapClient&MockObject $mockClient;

    protected function setUp(): void
    {
        $this->mockClient = $this->createMock(LdapClient::class);
        $this->subject = new RangeRetrieval($this->mockClient);;
    }
    
    public function test_it_should_get_a_specific_ranged_attribute_from_an_entry_if_it_exists(): void
    {
        self::assertEquals(
            'member',
            $this->subject->getRanged(Entry::create(
                'dc=foo',
                ['member;range=0-1500' => [], 'foo' => []]
            ), 'member')?->getName(),
        );
    }
    
    public function test_it_should_return_null_on_a_request_for_a_specific_ranged_attribute_that_does_not_exist(): void
    {
        self::assertNull($this->subject->getRanged(
            Entry::create(
                'dc=foo',
                ['member;range=0-1500' => [], 'foo' => []]
            ),
            'bar'
        ));
    }
    
    public function test_it_should_get_all_ranged_attributes_for_an_entry_as_an_array(): void
    {
        self::assertCount(
            2,
            $this->subject->getAllRanged(Entry::create(
                'dc=foo',
                ['member;range=0-1500' => [], 'foo' => [], 'bar;range=0-1000' => []]
            ))
        );
    }

    public function test_it_should_return_whether_an_entry_has_an_ranged_attributes(): void
    {
        self::assertFalse($this->subject->hasRanged(
            Entry::create(
                'dc=foo',
                ['member' => [], 'foo' => []]
            )
        ));
        self::assertTrue($this->subject->hasRanged(
            Entry::create(
                'dc=foo',
                ['member;range=0-1500' => [], 'foo' => []]
            )
        ));
    }
    
    public function test_it_should_return_whether_an_entry_has_a_specific_ranged_attribute(): void
    {
        self::assertFalse($this->subject->hasRanged(
            Entry::create(
                'dc=foo',
                ['member;range=0-1500' => [], 'foo' => []],
            ),
            'foo'
        ));
        self::assertTrue($this->subject->hasRanged(
            Entry::create(
                'dc=foo',
                ['member;range=0-1500' => [], 'foo' => []],
            ),
            'member',
        ));
    }
    
    public function test_it_should_check_if_a_ranged_attribute_has_more_values_to_retrieve(): void
    {
        self::assertFalse($this->subject->hasMoreValues(new Attribute('member')));
        self::assertFalse($this->subject->hasMoreValues(new Attribute('member;range=0-*')));
    }
    
    public function test_it_should_get_more_values_for_a_ranged_attribute(): void
    {
        $attrResult = new Attribute('member;range=1501-2000');
        $entry = new Entry('dc=foo', $attrResult);

        $this->mockClient
            ->expects($this->once())
            ->method('readOrFail')
            ->with(
                'dc=foo',
                $this->callback(function ($attr) {
                    /** @var Attribute[] $attr */
                    return $attr[0]->getOptions()->first()?->getLowRange() == '1501'
                        && $attr[0]->getOptions()->first()?->getHighRange() == '*';
                })
            )
            ->willReturn($entry);

        self::assertEquals(
            $attrResult,
            $this->subject->getMoreValues(
                'dc=foo',
                new Attribute('member;range=0-1500')
            )
        );
    }
    
    public function test_it_should_use_a_specific_ranged_amount_of_values_to_retrieve_if_specified(): void
    {
        $attrResult = new Attribute('member;range=1501-1600');
        $entry = new Entry('dc=foo', $attrResult);

        $this->mockClient
            ->expects($this->once())
            ->method('readOrFail')
            ->with(
                'dc=foo',
                $this->callback(function ($attr) {
                    /** @var Attribute[] $attr */
                    return $attr[0]->getOptions()->first()?->getLowRange() === '1501'
                        && $attr[0]->getOptions()->first()->getHighRange() === '1600';
                })
            )
            ->willReturn($entry);

        self::assertEquals(
            $attrResult,
            $this->subject->getMoreValues(
                'dc=foo',
                new Attribute('member;range=0-1500'),
                100,
            )
        );
    }
    
    public function test_it_should_retrieve_all_values_for_a_specific_attribute(): void
    {
        $entry1 = new Entry('dc=foo', new Attribute('member;range=0-1500', 'foo'));
        $entry2 = new Entry('dc=foo', new Attribute('member;range=1501-*', 'bar'));

        $this->mockClient
            ->expects($this->exactly(2))
            ->method('readOrFail')
            ->will($this->onConsecutiveCalls(
                $entry1,
                $entry2,
            ));

        self::assertEquals(
            ['foo', 'bar'],
            $this->subject->getAllValues(
                'dc=foo',
                'member',
            )->getValues(),
        );
    }
}
