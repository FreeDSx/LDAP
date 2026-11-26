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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\NoDeferredLinks;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Sync\Consumer\LinkedValueFilter;
use FreeDSx\Ldap\Sync\Consumer\ReplicaMoves;
use FreeDSx\Ldap\Sync\Consumer\VerbatimStorageApplier;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Sync\VerbatimStorageApplierTests;

final class VerbatimStorageApplierTest extends TestCase
{
    use VerbatimStorageApplierTests;

    protected function setUp(): void
    {
        $linked = new LinkedAttributes(SchemaResource::Core->load());
        $storage = new InMemoryStorage(linkedAttributes: $linked);
        $this->reader = $storage;
        $this->writer = $storage;
        $this->subject = new VerbatimStorageApplier(
            $storage,
            $storage,
            $storage,
            $storage,
            new ReplicaMoves(
                $storage,
                $storage,
                $storage,
            ),
            new NoDeferredLinks(),
            new LinkedValueFilter($linked),
        );
    }
}
