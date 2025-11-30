<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use PHPUnit\Framework\TestCase;

final class SyncRequestTest extends TestCase
{
    private SyncRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new SyncRequest();
    }

    public function test_it_should_get_constructed_with_a_present_filter_by_default(): void
    {
        self::assertEquals(
            Filters::present('objectClass'),
            $this->subject->getFilter()
        );
    }

    public function test_it_should_set_and_get_the_setId_handler(): void
    {
        $handler = fn (SyncIdSetResult $result) => $result->getEntryUuids();

        $this->subject->useIdSetHandler($handler);

        self::assertSame(
            $handler,
            $this->subject->getIdSetHandler()
        );
    }
}
