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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;

/**
 * Bulk-imports entries into an EntryStorageInterface under a single atomic write.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LdapImporter
{
    public function __construct(
        private EntryStorageInterface $storage,
        private OperationalAttributeGenerator $operationalAttrs = new OperationalAttributeGenerator(),
        private ?SchemaValidator $validator = null,
    ) {}

    /**
     * Stream entries into storage under a single atomic write.
     *
     * Input must be in depth-first order (each entry's parent appears before its children). Unsorted input will fail
     * at the parent check.
     *
     * @param iterable<Entry> $entries
     * @param Dn $creatorDn recorded as creatorsName/modifiersName on the imported entries.
     * @param bool $ignoreValidation when true, skips parent and schema checks. only do this if you know what you're doing.
     * @throws InvalidArgumentException when the creator DN is malformed, or a non-top-level entry's parent is not present in storage yet
     * @throws OperationException when an entry violates the schema and validation mode is strict
     */
    public function importEntries(
        iterable $entries,
        Dn $creatorDn = new Dn(''),
        bool $ignoreValidation = false,
    ): void {
        $this->assertValidCreatorDn($creatorDn);

        $this->storage->atomic(function (EntryStorageInterface $storage) use ($entries, $creatorDn, $ignoreValidation): void {
            foreach ($entries as $entry) {
                if (!$ignoreValidation) {
                    $this->assertParentExists(
                        $storage,
                        $entry->getDn(),
                    );
                }

                $this->validateForImport(
                    $entry,
                    $ignoreValidation,
                );
                $this->operationalAttrs->applyForBulkLoad(
                    $entry,
                    $creatorDn->toString(),
                );
                $storage->store(
                    $entry,
                    rebuildIndexes: true,
                );
            }
        });
    }

    /**
     * @throws InvalidArgumentException
     */
    private function assertParentExists(
        EntryStorageInterface $storage,
        Dn $dn,
    ): void {
        $parent = $dn->normalize()->getParent();

        if ($parent === null || $parent->getParent() === null) {
            return;
        }

        if ($storage->exists($parent)) {
            return;
        }

        throw new InvalidArgumentException(sprintf(
            'Parent entry "%s" does not exist for "%s".',
            $parent->toString(),
            $dn->toString(),
        ));
    }

    /**
     * Validates a bulk-loaded entry as a system-initiated add; only strict mode rejects violations.
     *
     * @throws OperationException
     */
    private function validateForImport(
        Entry $entry,
        bool $ignoreValidation,
    ): void {
        $validator = $this->validator;

        if ($ignoreValidation || $validator === null) {
            return;
        }
        if ($validator->mode() !== SchemaValidationMode::Strict) {
            return;
        }

        $validator->validateAdd(
            $entry,
            true,
        );
    }

    /**
     * @throws InvalidArgumentException when the creator DN is malformed
     */
    private function assertValidCreatorDn(Dn $creatorDn): void
    {
        if (Dn::isValid($creatorDn)) {
            return;
        }

        throw new InvalidArgumentException(sprintf(
            'The import creator DN "%s" is not a valid DN.',
            $creatorDn->toString(),
        ));
    }
}
