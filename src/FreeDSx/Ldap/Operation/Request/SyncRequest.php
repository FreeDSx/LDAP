<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Operation\Request;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\SyncHandlerInterface;

class SyncRequest extends SearchRequest
{
    private SyncHandlerInterface $syncHandler;

    public function __construct(
        SyncHandlerInterface $syncHandler,
        FilterInterface $filter,
        string|Attribute ...$attributes
    ) {
        $this->syncHandler = $syncHandler;

        parent::__construct(
            $filter,
            ...$attributes
        );
    }

    public function getSyncHandler(): SyncHandlerInterface
    {
        return $this->syncHandler;
    }
}
