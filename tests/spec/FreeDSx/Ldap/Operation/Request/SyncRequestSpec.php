<?php

declare(strict_types=1);

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use PhpSpec\ObjectBehavior;

class SyncRequestSpec extends ObjectBehavior
{
    public function it_should_get_constructed_with_a_present_filter_by_default(): void
    {
        $this->getFilter()
            ->shouldBeLike(Filters::present('objectClass'));
    }

    public function it_should_set_and_get_the_setId_handler(): void
    {
        $handler = fn(SyncIdSetResult $result) => $result->getEntryUuids();

        $this->useSyncIdSetHandler($handler)
            ->shouldBeEqualTo($this);
        $this->getSyncIdSetHandler()
            ->shouldBeEqualTo($handler);
    }
}
