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

namespace FreeDSx\Ldap\Schema\Validation;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Schema;

/**
 * Resolves the full MUST and MAY attribute sets by walking the object class inheritance chain.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ObjectClassChain
{
    /**
     * The classes the chain was resolved from.
     *
     * @var list<ObjectClass>
     */
    public array $classes;

    /**
     * The structural classes among them.
     *
     * @var list<ObjectClass>
     */
    public array $structural;

    /**
     * The structural class whose superclass chain covers every other, or null when they do not form one chain.
     */
    public ?ObjectClass $structuralHead;

    /**
     * Lowercased canonical attribute names that are required.
     *
     * @var list<string>
     */
    public array $must;

    /**
     * Lowercased canonical attribute names that are permitted.
     *
     * @var list<string>
     */
    public array $may;

    /**
     * @param list<ObjectClass> $objectClasses
     */
    public function __construct(
        Schema $schema,
        array $objectClasses,
    ) {
        $must = [];
        $may = [];
        $chain = self::withSuperclasses(
            $schema,
            $objectClasses,
        );

        foreach ($chain as $oc) {
            foreach ($oc->must as $name) {
                $must[] = strtolower($schema->getAttributeType($name)?->names[0] ?? $name);
            }

            foreach ($oc->may as $name) {
                $may[] = strtolower($schema->getAttributeType($name)?->names[0] ?? $name);
            }
        }

        $this->must = array_values(array_unique($must));
        $this->may = array_values(array_unique($may));
        $this->classes = $objectClasses;
        $this->structural = array_values(array_filter(
            $objectClasses,
            static fn(ObjectClass $oc): bool => $oc->type === ObjectClassType::StructuralClass,
        ));
        $this->structuralHead = self::mostSubordinateOf(
            $schema,
            $this->structural,
        );
    }

    /**
     * Resolved from the entry's objectClass values, skipping any the schema does not define.
     */
    public static function forEntry(
        Schema $schema,
        Entry $entry,
    ): self {
        return new self(
            $schema,
            array_values(array_filter(array_map(
                static fn(string $name): ?ObjectClass => $schema->getObjectClass($name),
                $entry->get('objectClass')?->getValues() ?? [],
            ))),
        );
    }

    /**
     * @param list<ObjectClass> $structural
     */
    private static function mostSubordinateOf(
        Schema $schema,
        array $structural,
    ): ?ObjectClass {
        foreach ($structural as $candidate) {
            if (self::coversAll($schema, $candidate, $structural)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * @param list<ObjectClass> $structural
     */
    private static function coversAll(
        Schema $schema,
        ObjectClass $head,
        array $structural,
    ): bool {
        $closure = self::withSuperclasses(
            $schema,
            [$head],
        );

        foreach ($structural as $oc) {
            if (!isset($closure[$oc->oid])) {
                return false;
            }
        }

        return true;
    }

    /**
     * The classes and their transitive superclasses, keyed by OID in the order they are reached.
     *
     * @param list<ObjectClass> $objectClasses
     * @return array<string, ObjectClass>
     */
    private static function withSuperclasses(
        Schema $schema,
        array $objectClasses,
    ): array {
        $visited = [];
        $queue = $objectClasses;

        while ($queue !== []) {
            $oc = array_shift($queue);

            if (isset($visited[$oc->oid])) {
                continue;
            }

            $visited[$oc->oid] = $oc;

            foreach ($oc->superClassOids as $superOid) {
                $super = $schema->getObjectClass($superOid);
                if ($super !== null) {
                    $queue[] = $super;
                }
            }
        }

        return $visited;
    }
}
