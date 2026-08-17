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

use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\WriteEntryOperationHandler;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
use FreeDSx\Ldap\Server\Backend\Storage\SearchStreamBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptionsFactory;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\SearchLimits;

/**
 * Wires a WritableStorageBackend for tests in one place.
 */
trait BackendFactoryTrait
{
    use FilterEvaluatorFactoryTrait;

    /**
     * Defaults to the core schema with validation off: filter evaluation reads the schema to tell an unrecognized
     * attribute type from one an entry merely lacks, so an empty schema would make every assertion Undefined.
     */
    private function makeWritableBackend(
        ?EntryStorageInterface $storage = null,
        ?SchemaValidationMode $validationMode = null,
        ?Schema $schema = null,
        ?SearchLimits $limits = null,
        ?ChangeRecorder $changeRecorder = null,
    ): WritableStorageBackend {
        $storage ??= new InMemoryStorage();
        $schema ??= SchemaResource::Core->load();
        $limits ??= new SearchLimits();
        $filterEvaluator = $this->makeFilterEvaluator(
            $schema,
            $storage,
        );

        return new WritableStorageBackend(
            storage: $storage,
            searchStream: new SearchStreamBuilder(
                $limits,
                $filterEvaluator,
                $this->makeDerivedResolver($storage),
            ),
            // Built from the same schema the rest of the backend reads, so the two cannot disagree.
            validator: new SchemaValidator(
                $schema,
                $validationMode ?? SchemaValidationMode::Off,
            ),
            listOptions: new StorageListOptionsFactory(
                $schema,
                $limits,
            ),
            filterEvaluator: $filterEvaluator,
            entryHandler: new WriteEntryOperationHandler(
                new EqualityComparatorResolver($schema),
            ),
            changeRecorder: $changeRecorder,
        );
    }
}
