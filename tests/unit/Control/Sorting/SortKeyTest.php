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

namespace Tests\Unit\FreeDSx\Ldap\Control\Sorting;

use FreeDSx\Ldap\Control\Sorting\SortKey;
use PHPUnit\Framework\TestCase;

class SortKeyTest extends TestCase
{
    private SortKey $subject;

    protected function setUp(): void
    {
        $this->subject = new SortKey('cn');
    }

    public function test_it_should_be_constructed_via_reverse_order(): void
    {
        $this->subject = new SortKey(attribute: 'cn', useReverseOrder: true);

        self::assertTrue($this->subject->getUseReverseOrder());
    }

    public function test_it_should_be_constructed_ascending(): void
    {
        $this->subject = SortKey::ascending('foo');

        self::assertFalse($this->subject->getUseReverseOrder());
        self::assertSame(
            'foo',
            $this->subject->getAttribute(),
        );
    }

    public function test_it_should_be_constructed_descending(): void
    {
        $this->subject = SortKey::descending('foo');

        self::assertTrue($this->subject->getUseReverseOrder());
        self::assertSame(
            'foo',
            $this->subject->getAttribute(),
        );
    }

    public function test_it_should_not_use_reverse_order_by_default(): void
    {
        self::assertFalse($this->subject->getUseReverseOrder());
    }

    public function test_it_should_set_the_attribute_to_use(): void
    {
        $this->subject->setAttribute('foo');

        self::assertSame(
            'foo',
            $this->subject->getAttribute(),
        );
    }

    public function test_it_should_set_the_ordering_rule(): void
    {
        $this->subject->setOrderingRule('foo');

        self::assertSame(
            'foo',
            $this->subject->getOrderingRule(),
        );
    }

    public function test_it_should_set_whether_to_use_reverse_order(): void
    {
        $this->subject->setUseReverseOrder(true);

        self::assertTrue($this->subject->getUseReverseOrder());
    }
}
