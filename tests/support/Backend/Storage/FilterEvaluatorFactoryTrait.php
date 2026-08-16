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

namespace Tests\Support\FreeDSx\Ldap\Backend\Storage;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedResolver;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluator;

/**
 * Builds a real FilterEvaluator, so tests needing genuine filter semantics do not each rebuild its dependencies.
 */
trait FilterEvaluatorFactoryTrait
{
    /**
     * @param ?Schema $schema Defaults to core; pass one only where a test needs a type core does not define, since an
     *                        unrecognized type evaluates to Undefined.
     */
    private function makeFilterEvaluator(
        ?Schema $schema = null,
        ?EntryStorageInterface $storage = null,
    ): FilterEvaluator {
        return new FilterEvaluator(
            $schema ?? SchemaResource::Core->load(),
            $this->makeDerivedResolver($storage),
        );
    }

    /**
     * @param ?EntryStorageInterface $storage Only hasSubordinates consults it, so it is mocked unless a test cares.
     */
    private function makeDerivedResolver(?EntryStorageInterface $storage = null): DerivedResolver
    {
        return new DerivedResolver(
            $storage ?? $this->createMock(EntryStorageInterface::class),
            new Dn('cn=Subschema'),
        );
    }
}
