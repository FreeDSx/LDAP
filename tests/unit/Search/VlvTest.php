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

use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Control\Vlv\VlvControl;
use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Vlv;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Unit\FreeDSx\Ldap\TestFactoryTrait;

final class VlvTest extends TestCase
{
    use TestFactoryTrait;

    private Vlv $subject;

    private LdapClient&MockObject $mockClient;

    private SearchRequest&MockObject $mockSearch;

    protected function setUp(): void
    {
        $this->mockClient = $this->createMock(LdapClient::class);
        $this->mockSearch = $this->createMock(SearchRequest::class);

        $this->subject = new Vlv(
            $this->mockClient,
            $this->mockSearch,
            'cn',
        );
    }

    public function test_it_should_accept_a_sort_key_as_a_sort_argument(): void
    {
        $this->subject = new Vlv(
            $this->mockClient,
            $this->mockSearch,
            new SortKey('foo'),
        );

        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->equalTo(new SortingControl(new SortKey('foo')))
            )
            ->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(50, 150, 0, 'foo')]
            ));

        $this->subject->getEntries();
    }

    public function test_it_should_accept_a_sort_control_as_a_sort_argument(): void
    {
        $this->subject = new Vlv(
            $this->mockClient,
            $this->mockSearch,
            new SortingControl(
                new SortKey('foo'),
                new SortKey('bar'),
            ),
        );

        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->equalTo(new SortingControl(
                    new SortKey('foo'),
                    new SortKey('bar'),
                ))
            )->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(50, 150, 0, 'foo')]
            ));

        $this->subject->getEntries();
    }

    public function test_it_should_set_the_offset_using_startAt(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with(
                $this->anything(),
                $this->equalTo(new VlvControl(
                    0,
                    100,
                    1000,
                    0,
                    null,
                    null
                )),
                $this->anything(),
            )->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(50, 150, 0, 'foo')]
            ));

        $this->subject->startAt(1000);
        $this->subject->getEntries();
    }

    public function test_it_should_set_the_offset_using_moveTo(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with(
                $this->anything(),
                $this->equalTo(new VlvControl(
                    0,
                    100,
                    1000,
                    0,
                    null,
                    null
                )),
                $this->anything(),
            )->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(50, 150, 0, 'foo')]
            ));

        $this->subject->moveTo(1000);
        $this->subject->getEntries();
    }

    public function test_it_should_return_null_on_position_if_nothing_has_happened(): void
    {
        self::assertNull($this->subject->position());
    }

    public function test_it_should_return_the_offset_on_a_call_to_position(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(250, 150, 0, 'foo')]
            ));

        $this->subject->getEntries();

        self::assertSame(
            250,
            $this->subject->position(),
        );
    }

    public function test_it_should_return_the_size_of_the_list_returned_from_the_server(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(0, 200, 0, 'foo')]
            ));

        $this->subject->getEntries();

        self::assertSame(
            200,
            $this->subject->listSize(),
        );
    }

    public function test_it_should_get_the_offset_returned_by_the_server_when_calling_list_offset(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(10, 200, 0, 'foo')]
            ));

        $this->subject->getEntries();

        self::assertSame(
            10,
            $this->subject->listOffset(),
        );
    }

    public function test_it_should_check_if_we_are_at_the_start_of_the_list(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(1, 200, 0, 'foo')],
            ));

        self::assertFalse($this->subject->isAtStartOfList());

        $this->subject->getEntries();

        self::assertTrue($this->subject->isAtStartOfList());
    }

    public function test_it_should_check_if_we_are_at_the_start_of_the_list_based_on_the_offset_and_before_value(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(101, 200, 0, 'foo')],
            ));

        $this->subject->beforePosition(100);

        self::assertFalse($this->subject->isAtStartOfList());

        $this->subject->getEntries();

        self::assertTrue($this->subject->isAtStartOfList());
    }

    public function test_it_should_check_if_we_are_at_the_end_of_the_list(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(200, 200, 0, 'foo')],
            ));

        self::assertFalse($this->subject->isAtEndOfList());

        $this->subject->getEntries();

        self::assertTrue($this->subject->isAtEndOfList());
    }

    public function test_it_should_check_if_we_are_at_the_end_of_the_list_based_on_the_offset_and_after_value(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(101, 200, 0, 'foo')],
            ));

        self::assertFalse($this->subject->isAtEndOfList());

        $this->subject->getEntries();

        self::assertTrue($this->subject->isAtEndOfList());
    }

    public function test_it_should_set_the_before_and_after_positions(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with(
                $this->anything(),
                $this->equalTo(new VlvControl(25, 75, 1, 0)),
                $this->anything(),
            )->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(1, 200, 0, 'foo')],
            ));

        $this->subject->beforePosition(25);
        $this->subject->afterPosition(75);

        $this->subject->getEntries();
    }

    public function test_it_should_indicate_the_position_as_a_percentage_if_specified(): void
    {
        $this->mockClient
            ->expects($this->once())
            ->method('sendAndReceive')
            ->with(
                $this->anything(),
                $this->equalTo(new VlvControl(0, 100, 1, 100)),
                $this->anything(),
            )->willReturn($this::makeSearchResponseFromEntries(
                controls: [new VlvResponseControl(150, 200, 0, 'foo')],
            ));

        $this->subject->asPercentage();
        $this->subject->getEntries();

        self::assertSame(
            75,
            $this->subject->position(),
        );
    }

    public function test_it_should_move_forward_as_a_percentage_if_specified(): void
    {
        $this->mockClient
            ->expects($this->atMost(2))
            ->method('sendAndReceive')
            ->will($this->onConsecutiveCalls(
                $this::makeSearchResponseFromEntries(
                    controls: [new VlvResponseControl(1, 200, 0, 'foo')],
                ),
                $this::makeSearchResponseFromEntries(
                    controls: [new VlvResponseControl(20, 200, 0, 'foo')],
                )
            ));

        $this->subject->asPercentage();
        $this->subject->getEntries();

        $this->subject->moveForward(9);
        $this->subject->getEntries();

        self::assertSame(
            10,
            $this->subject->position(),
        );
        self::assertSame(
            20,
            $this->subject->listOffset(),
        );
    }

    public function test_it_should_move_backward_as_a_percentage_if_specified(): void
    {
        $this->mockClient
            ->expects($this->atMost(2))
            ->method('sendAndReceive')
            ->will($this->onConsecutiveCalls(
                $this::makeSearchResponseFromEntries(
                    controls: [new VlvResponseControl(100, 200, 0, 'foo')],
                ),
                $this::makeSearchResponseFromEntries(
                    controls: [new VlvResponseControl(80, 200, 0, 'foo')],
                )
            ));

        $this->subject->asPercentage(true);
        $this->subject->startAt(50);

        $this->subject->getEntries();
        $this->subject->moveBackward(10);
        $this->subject->getEntries();

        self::assertSame(
            40,
            $this->subject->position(),
        );
        self::assertSame(
            80,
            $this->subject->listOffset(),
        );
    }
}
