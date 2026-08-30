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

namespace FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\Utility\Uuid;

/**
 * Injects server-managed operational attributes into entries on write.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationalAttributeGenerator
{
    public function __construct(
        private ?Schema $schema = null,
    ) {}

    /**
     * Sets createTimestamp, modifyTimestamp, creatorsName, modifiersName, entryUUID, and structuralObjectClass.
     */
    public function applyForAdd(
        Entry $entry,
        WriteContext $context,
    ): void {
        $timestamp = $this->generateTimestamp();
        $boundDn = $context->getBoundDn() ?? '';

        $entry->set(
            AttributeTypeOid::NAME_CREATE_TIMESTAMP,
            $timestamp,
        );
        $entry->set(
            AttributeTypeOid::NAME_MODIFY_TIMESTAMP,
            $timestamp,
        );
        $entry->set(
            AttributeTypeOid::NAME_CREATORS_NAME,
            $boundDn,
        );
        $entry->set(
            AttributeTypeOid::NAME_MODIFIERS_NAME,
            $boundDn,
        );
        $entry->set(
            AttributeTypeOid::NAME_ENTRY_UUID,
            Uuid::v4(),
        );
        $this->applySuperclasses($entry);

        $structuralOc = $this->resolveStructuralObjectClass($entry);

        if ($structuralOc !== null) {
            $entry->set(
                AttributeTypeOid::NAME_STRUCTURAL_OBJECT_CLASS,
                $structuralOc,
            );
        }
    }

    /**
     * Fills server-managed attributes on a bulk-loaded entry, preserving any the source supplied; creator/modifier
     * default to the given actor DN.
     */
    public function applyForBulkLoad(
        Entry $entry,
        string $actorDn = '',
    ): void {
        $timestamp = $this->generateTimestamp();

        $this->setIfMissing(
            $entry,
            AttributeTypeOid::NAME_ENTRY_UUID,
            Uuid::v4(),
        );
        $this->setIfMissing(
            $entry,
            AttributeTypeOid::NAME_CREATE_TIMESTAMP,
            $timestamp,
        );
        $this->setIfMissing(
            $entry,
            AttributeTypeOid::NAME_MODIFY_TIMESTAMP,
            $timestamp,
        );
        $this->setIfMissing(
            $entry,
            AttributeTypeOid::NAME_CREATORS_NAME,
            $actorDn,
        );
        $this->setIfMissing(
            $entry,
            AttributeTypeOid::NAME_MODIFIERS_NAME,
            $actorDn,
        );
        $this->applySuperclasses($entry);
        $this->applyStructuralObjectClass($entry);
    }

    /**
     * Updates modifyTimestamp and modifiersName, and supplies any superclass a changed objectClass now implies.
     */
    public function applyForModify(
        Entry $entry,
        WriteContext $context,
    ): void {
        $entry->set(
            AttributeTypeOid::NAME_MODIFY_TIMESTAMP,
            $this->generateTimestamp(),
        );
        $entry->set(
            AttributeTypeOid::NAME_MODIFIERS_NAME,
            $context->getBoundDn() ?? '',
        );
        $this->applySuperclasses($entry);
    }

    /**
     * RFC 4512 3.3: the superclasses of every named class are added implicitly.
     */
    private function applySuperclasses(Entry $entry): void
    {
        $attribute = $entry->get(AttributeTypeOid::NAME_OBJECT_CLASS);
        if ($attribute === null) {
            return;
        }

        $missing = $this->missingSuperclassesOf(array_values($attribute->getValues()));
        if ($missing !== []) {
            $attribute->add(...$missing);
        }
    }

    /**
     * @param list<string> $names
     * @return list<string>
     */
    private function missingSuperclassesOf(array $names): array
    {
        $seen = array_fill_keys(array_map(strtolower(...), $names), true);
        $queue = $names;
        $missing = [];

        while ($queue !== []) {
            $supers = array_values(array_filter(
                $this->superclassNamesOf((string) array_shift($queue)),
                static fn(string $name): bool => !isset($seen[strtolower($name)]),
            ));

            $seen += array_fill_keys(array_map(strtolower(...), $supers), true);
            $missing = [...$missing, ...$supers];
            $queue = [...$queue, ...$supers];
        }

        return $missing;
    }

    /**
     * A class the schema does not define has no superclasses to supply, so validation reports it rather than this.
     *
     * @return list<string>
     */
    private function superclassNamesOf(string $name): array
    {
        $schema = $this->schema;
        $class = $schema?->getObjectClass($name);

        if ($schema === null || $class === null) {
            return [];
        }

        return array_values(array_filter(array_map(
            static fn(string $oid): ?string => $schema->getObjectClass($oid)?->names[0],
            $class->superClassOids,
        )));
    }

    private function generateTimestamp(): string
    {
        return gmdate('YmdHis') . 'Z';
    }

    private function setIfMissing(
        Entry $entry,
        string $attribute,
        string $value,
    ): void {
        if ($entry->has($attribute)) {
            return;
        }

        $entry->set(
            $attribute,
            $value,
        );
    }

    private function applyStructuralObjectClass(Entry $entry): void
    {
        if ($entry->has(AttributeTypeOid::NAME_STRUCTURAL_OBJECT_CLASS)) {
            return;
        }

        $structuralOc = $this->resolveStructuralObjectClass($entry);

        if ($structuralOc === null) {
            return;
        }

        $entry->set(
            AttributeTypeOid::NAME_STRUCTURAL_OBJECT_CLASS,
            $structuralOc,
        );
    }

    private function resolveStructuralObjectClass(Entry $entry): ?string
    {
        if ($this->schema === null) {
            return null;
        }

        $objectClassAttr = $entry->get(
            'objectClass',
            true,
        );

        if ($objectClassAttr === null) {
            return null;
        }

        $structural = $this->collectStructuralClasses(
            $this->schema,
            $objectClassAttr->getValues(),
        );

        if ($structural === []) {
            return null;
        }

        foreach ($structural as $candidate) {
            if (!$this->isSuperclassOfAny($candidate, $structural, $this->schema)) {
                return $candidate->names[0] ?? $candidate->oid;
            }
        }

        $first = array_values($structural)[0];

        return $first->names[0] ?? $first->oid;
    }

    /**
     * @param string[] $names
     * @return array<string, ObjectClass>
     */
    private function collectStructuralClasses(
        Schema $schema,
        array $names,
    ): array {
        $structural = [];

        foreach ($names as $name) {
            $oc = $schema->getObjectClass($name);

            if ($oc === null || $oc->type !== ObjectClassType::StructuralClass) {
                continue;
            }

            $structural[$oc->oid] = $oc;
        }

        return $structural;
    }

    /**
     * @param array<string, ObjectClass> $structural
     */
    private function isSuperclassOfAny(
        ObjectClass $candidate,
        array $structural,
        Schema $schema,
    ): bool {
        foreach ($structural as $other) {
            if ($other->oid === $candidate->oid) {
                continue;
            }

            if ($this->isDirectSuperclassOf($candidate, $other, $schema)) {
                return true;
            }
        }

        return false;
    }

    private function isDirectSuperclassOf(
        ObjectClass $candidate,
        ObjectClass $other,
        Schema $schema,
    ): bool {
        foreach ($other->superClassOids as $superOid) {
            $resolved = $schema->getObjectClass($superOid);

            if ($resolved !== null && $resolved->oid === $candidate->oid) {
                return true;
            }
        }

        return false;
    }
}
