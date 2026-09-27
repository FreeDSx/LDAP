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

use Closure;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SchemaValidationException;
use FreeDSx\Ldap\Exception\SchemaViolationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\Matching\EquivalentValues;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Schema\Validation\Syntax\SyntaxValidatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;

/**
 * Validates entries against the schema for add and modify operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SchemaValidator
{
    /**
     * What an attribute may hold when its type declares no cap of its own.
     *
     * Enough for any reasonable entry, and well below the size at which a single entry becomes expensive to read and write.
     */
    public const DEFAULT_MAX_VALUES = 10000;

    private const EXTENSIBLE_OBJECT = 'extensibleObject';

    /**
     * The operational attributes draft-zeilenga-ldap-relax §3.6 lets a relaxed Add supply.
     */
    private const SETTABLE_ON_ADD = [
        AttributeTypeOid::NAME_ENTRY_UUID,
        AttributeTypeOid::NAME_CREATE_TIMESTAMP,
        AttributeTypeOid::NAME_MODIFY_TIMESTAMP,
        AttributeTypeOid::NAME_CREATORS_NAME,
        AttributeTypeOid::NAME_MODIFIERS_NAME,
    ];

    /**
     * The same on Modify less entryUUID, which replication and the password policy forward address an entry by.
     */
    private const SETTABLE_ON_MODIFY = [
        AttributeTypeOid::NAME_CREATE_TIMESTAMP,
        AttributeTypeOid::NAME_MODIFY_TIMESTAMP,
        AttributeTypeOid::NAME_CREATORS_NAME,
        AttributeTypeOid::NAME_MODIFIERS_NAME,
    ];

    private readonly AttributeSyntaxResolver $syntaxResolver;

    private readonly EqualityComparatorResolver $equalityResolver;

    private readonly LinkedAttributes $linked;

    /**
     * @var array<string, int> Keyed on the base type, resolved on first use since the schema is fixed after startup.
     */
    private array $valueLimits = [];

    public function __construct(
        private readonly Schema $schema,
        private readonly SchemaValidationMode $mode,
        ?AttributeSyntaxResolver $syntaxResolver = null,
        ?EqualityComparatorResolver $equalityResolver = null,
        private readonly int $maxValues = self::DEFAULT_MAX_VALUES,
        ?LinkedAttributes $linked = null,
    ) {
        $this->syntaxResolver = $syntaxResolver ?? new AttributeSyntaxResolver($schema);
        $this->equalityResolver = $equalityResolver ?? new EqualityComparatorResolver($schema);
        $this->linked = $linked ?? new LinkedAttributes($schema);
    }

    public function mode(): SchemaValidationMode
    {
        return $this->mode;
    }

    /**
     * Validates an entry before it is added to storage.
     *
     * @param bool $isSystem Skip the NO-USER-MODIFICATION check for server-initiated writes.
     * @throws SchemaValidationException
     */
    public function validateAdd(
        Entry $entry,
        bool $isSystem = false,
    ): void {
        if ($this->mode === SchemaValidationMode::Off) {
            return;
        }
        $checks = [fn() => $this->checkAttributeSyntaxes($entry)];

        if (!$isSystem) {
            array_push(
                $checks,
                ...$this->noUserModificationChecks(
                    array_map(
                        static fn(Attribute $attribute): string => $attribute->getName(),
                        $entry->getAttributes(),
                    ),
                    self::SETTABLE_ON_ADD,
                    'Attribute "%s" cannot be set by users.',
                ),
            );
        }
        $checks[] = fn() => $this->checkDistinctAttributeDescriptions($entry);
        $checks[] = fn() => $this->checkNoEquivalentValues($entry);

        if (!$entry->getDn()->isRootDse()) {
            $checks[] = fn() => $this->checkNamingAttributesAreMatchable($entry->getDn()->getRdn());
        }

        $this->assertAll(
            ...$checks,
            ...$this->structureChecks($entry),
        );
    }

    /**
     * Validates the changes and resulting entry from an update operation.
     *
     * @param bool $isSystem Skip the NO-USER-MODIFICATION check for server-initiated writes.
     * @throws SchemaValidationException
     */
    public function validateModify(
        UpdateCommand $command,
        Entry $result,
        bool $isSystem = false,
    ): void {
        if ($this->mode === SchemaValidationMode::Off) {
            return;
        }
        $checks = [fn() => $this->checkAttributeSyntaxes($result)];

        if (!$isSystem) {
            array_push(
                $checks,
                ...$this->noUserModificationChecks(
                    array_map(
                        static fn(Change $change): string => $change->getAttribute()->getName(),
                        $command->changes,
                    ),
                    self::SETTABLE_ON_MODIFY,
                    'Attribute "%s" cannot be modified by users.',
                ),
            );
        }
        // Only what the change touched, since the rest was already checked when it was written.
        $checks[] = fn() => $this->checkNoEquivalentValues(
            $result,
            self::namesChangedBy($command->changes),
        );
        $checks[] = fn() => $this->checkStructuralClassUnchanged($result);

        $this->assertAll(
            ...$checks,
            ...$this->structureChecks($result),
        );
    }

    /**
     * Validates the entry resulting from a modifyDn, where the new RDN adds values and the old one may remove them.
     *
     * @param bool $isSystem Skip the NO-USER-MODIFICATION check for server-initiated writes.
     * @throws SchemaValidationException
     */
    public function validateModifyDn(
        Entry $result,
        Rdn $newRdn,
        bool $isSystem = false,
    ): void {
        if ($this->mode === SchemaValidationMode::Off) {
            return;
        }
        $checks = [fn() => $this->checkAttributeSyntaxes($result)];

        // The new RDN is client-supplied, so the values it puts on the entry face the same restriction as a modify.
        if (!$isSystem) {
            array_push(
                $checks,
                ...$this->noUserModificationChecks(
                    array_map(
                        static fn(Rdn $component): string => $component->getName(),
                        $newRdn->getAll(),
                    ),
                    [],
                    'Attribute "%s" cannot be set by users.',
                ),
            );
        }
        $checks[] = fn() => $this->checkNoEquivalentValues($result);
        $checks[] = fn() => $this->checkNamingAttributesAreMatchable($newRdn);

        $this->assertAll(
            ...$checks,
            ...$this->structureChecks($result),
        );
    }

    /**
     * Holds an attribute's values to its type's syntax.
     *
     * @throws OperationException when a value does not conform
     */
    public function validateValues(Attribute $attribute): void
    {
        if ($this->mode === SchemaValidationMode::Off) {
            return;
        }
        $attrType = $this->schema->getAttributeType($attribute->getName());

        if ($attrType === null) {
            return;
        }
        $validator = $this->syntaxResolver->validatorFor($attrType);

        if ($validator === null) {
            return;
        }

        $this->checkValuesConform(
            $attribute,
            $validator,
        );
    }

    /**
     * Checked apart, so a settable attribute the Relax control waives cannot hide one it does not.
     *
     * @param array<string> $names
     * @param list<string> $settable
     * @return list<Closure(): void>
     */
    private function noUserModificationChecks(
        array $names,
        array $settable,
        string $message,
    ): array {
        return [
            fn() => $this->checkNoUserModification(
                $names,
                $settable,
                SchemaRule::NoUserModification,
                $message,
            ),
            fn() => $this->checkNoUserModification(
                $names,
                $settable,
                SchemaRule::SettableOperationalAttribute,
                $message,
            ),
        ];
    }

    /**
     * Reports the NO-USER-MODIFICATION attributes a write supplies that fall under the given rule.
     *
     * @param array<string> $names
     * @param list<string> $settable
     * @throws OperationException
     */
    private function checkNoUserModification(
        array $names,
        array $settable,
        SchemaRule $rule,
        string $message,
    ): void {
        $wantSettable = $rule === SchemaRule::SettableOperationalAttribute;

        foreach ($names as $name) {
            $attrType = $this->schema->getAttributeType($name);

            if ($attrType === null || !$attrType->noUserModification) {
                continue;
            }
            if (in_array($attrType->primaryName(), $settable, true) !== $wantSettable) {
                continue;
            }

            $this->fail(
                sprintf($message, $name),
                ResultCode::CONSTRAINT_VIOLATION,
                $rule,
            );
        }
    }

    /**
     * RFC 4512 §2.5.1: a type specifying no equality matching cannot be used for naming.
     *
     * @throws OperationException
     */
    private function checkNamingAttributesAreMatchable(Rdn $rdn): void
    {
        foreach ($rdn->getAll() as $component) {
            $attrType = $this->schema->getAttributeType($component->getName());
            // An undefined type is reported by its own check, which says something more useful about it.
            if ($attrType === null || $this->schema->getEqualityRuleOid($attrType->oid) !== null) {
                continue;
            }

            $this->fail(
                sprintf(
                    'Attribute "%s" has no equality matching rule and cannot name an entry.',
                    $component->getName(),
                ),
                ResultCode::NAMING_VIOLATION,
                SchemaRule::NamingAttributes,
            );
        }
    }

    /**
     * RFC 4512 §2.4.2: the structural object class of an entry shall not be changed.
     *
     * @throws OperationException
     */
    private function checkStructuralClassUnchanged(Entry $result): void
    {
        $recorded = $result->get('structuralObjectClass')?->firstValue();

        if ($recorded === null) {
            return;
        }

        $structural = $this->structuralClassOf($this->collectObjectClasses($result));

        if ($structural === null || strcasecmp($structural, $recorded) === 0) {
            return;
        }

        $this->fail(
            sprintf('The structural object class cannot be changed from "%s" to "%s".', $recorded, $structural),
            ResultCode::OBJECT_CLASS_MODS_PROHIBITED,
            SchemaRule::StructuralClassChange,
        );
    }

    /**
     * @param list<ObjectClass> $objectClasses
     */
    private function structuralClassOf(array $objectClasses): ?string
    {
        $structural = array_values(array_filter(
            $objectClasses,
            fn(ObjectClass $oc) => $oc->type === ObjectClassType::StructuralClass,
        ));

        return $this->mostSubordinateOf($structural)?->names[0] ?? null;
    }

    /**
     * Runs every check, so a violation a caller may waive cannot hide one it may not.
     *
     * @throws SchemaValidationException
     */
    private function assertAll(Closure ...$checks): void
    {
        $violations = [];

        foreach ($checks as $check) {
            try {
                $check();
            } catch (SchemaViolationException $violation) {
                $violations[] = $violation;
            }
        }

        if ($violations !== []) {
            throw new SchemaValidationException($violations);
        }
    }

    /**
     * @return list<Closure(): void>
     */
    private function structureChecks(Entry $entry): array
    {
        $objectClasses = $this->collectObjectClasses($entry);
        $chain = new ObjectClassChain(
            $this->schema,
            $objectClasses,
        );
        $checks = [
            fn() => $this->checkStructuralClass(
                $entry,
                $objectClasses,
            ),
            fn() => $this->checkRequiredAttributes(
                $entry,
                $chain->must,
            ),
            fn() => $this->checkAttributeTypesAreDefined($entry),
        ];

        // RFC 4512 §4.3 lets extensibleObject hold any user attribute, so only the MAY list is waived; the
        // structural class, the MUST attributes, and the types themselves still apply.
        if (!$this->hasExtensibleObject($entry)) {
            $checks[] = fn() => $this->checkAllowedAttributes(
                $entry,
                $chain->must,
                $chain->may,
            );
        }
        $checks[] = fn() => $this->checkSingleValuedAttributes($entry);
        $checks[] = fn() => $this->checkValueCounts($entry);

        return $checks;
    }

    /**
     * RFC 4512 §2.2: all attributes of an entry must have distinct attribute descriptions.
     *
     * @throws OperationException
     */
    private function checkDistinctAttributeDescriptions(Entry $entry): void
    {
        $seen = [];

        foreach ($entry->getAttributes() as $attr) {
            $description = strtolower($attr->getDescription());

            if (isset($seen[$description])) {
                $this->fail(
                    sprintf('Attribute "%s" is supplied more than once.', $attr->getDescription()),
                    ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
                    SchemaRule::DistinctDescriptions,
                );
            }

            $seen[$description] = true;
        }
    }

    /**
     * RFC 4511 §4.1.7: no two of an attribute's values may be equivalent.
     *
     * @param ?array<string, true> $only Lowercased attribute names to check, or null for every attribute.
     * @throws OperationException
     */
    private function checkNoEquivalentValues(
        Entry $entry,
        ?array $only = null,
    ): void {
        foreach ($entry->getAttributes() as $attr) {
            if ($only !== null && !isset($only[Attribute::normalizeName($attr->getDescription())])) {
                continue;
            }

            if (!$this->hasEquivalentValues($attr)) {
                continue;
            }

            $this->fail(
                sprintf('Attribute "%s" is supplied an equivalent value more than once.', $attr->getDescription()),
                ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
                SchemaRule::EquivalentValues,
            );
        }
    }

    /**
     * The attribute types a change list touches, normalized the way every other type lookup normalizes.
     *
     * @param Change[] $changes
     * @return array<string, true>
     */
    private static function namesChangedBy(array $changes): array
    {
        $names = [];

        foreach ($changes as $change) {
            $names[Attribute::normalizeName($change->getAttribute()->getDescription())] = true;
        }

        return $names;
    }

    /**
     * Grouped by the rule's index key, so equality is only asked of values that could answer it.
     */
    private function hasEquivalentValues(Attribute $attr): bool
    {
        return EquivalentValues::firstDuplicate(
            $this->equalityResolver->for($attr->getName()),
            $attr->getValues(),
        ) !== null;
    }

    /**
     * @throws OperationException
     */
    private function checkAttributeTypesAreDefined(Entry $entry): void
    {
        foreach ($entry->getAttributes() as $attr) {
            if ($this->schema->getAttributeType($attr->getName()) !== null) {
                continue;
            }

            $this->fail(
                sprintf('Undefined attribute type: "%s".', $attr->getName()),
                ResultCode::UNDEFINED_ATTRIBUTE_TYPE,
                SchemaRule::DefinedAttributeTypes,
            );
        }
    }

    private function hasExtensibleObject(Entry $entry): bool
    {
        foreach ($entry->get('objectClass')?->getValues() ?? [] as $oc) {
            if (strcasecmp($oc, self::EXTENSIBLE_OBJECT) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<ObjectClass>
     */
    private function collectObjectClasses(Entry $entry): array
    {
        return array_values(array_filter(
            array_map(
                fn(string $name) => $this->schema->getObjectClass($name),
                $entry->get('objectClass')?->getValues() ?? [],
            ),
        ));
    }

    /**
     * @param list<ObjectClass> $objectClasses
     * @throws OperationException
     */
    private function checkStructuralClass(
        Entry $entry,
        array $objectClasses,
    ): void {
        $structural = array_values(array_filter(
            $objectClasses,
            fn(ObjectClass $oc) => $oc->type === ObjectClassType::StructuralClass,
        ));

        if ($structural === []) {
            $this->fail(
                sprintf(
                    'Entry "%s" must have at least one structural object class.',
                    $entry->getDn()->toString(),
                ),
                ResultCode::OBJECT_CLASS_VIOLATION,
                SchemaRule::StructuralClass,
            );
        }

        if ($this->hasSingleStructuralChain($structural)) {
            return;
        }

        $this->fail(
            sprintf(
                'Entry "%s" must not combine unrelated structural object classes.',
                $entry->getDn()->toString(),
            ),
            ResultCode::OBJECT_CLASS_VIOLATION,
            SchemaRule::StructuralClass,
        );
    }

    /**
     * Whether one structural class is the head of a single chain covering all the others.
     *
     * @param list<ObjectClass> $structural
     */
    private function hasSingleStructuralChain(array $structural): bool
    {
        return $this->mostSubordinateOf($structural) !== null;
    }

    /**
     * The one class whose superclass chain covers every other structural class, or null when they do not form one.
     *
     * @param list<ObjectClass> $structural
     */
    private function mostSubordinateOf(array $structural): ?ObjectClass
    {
        foreach ($structural as $candidate) {
            if ($this->coversAllStructural($candidate, $structural)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * @param list<ObjectClass> $structural
     */
    private function coversAllStructural(
        ObjectClass $head,
        array $structural,
    ): bool {
        $closure = $this->superclassClosure($head);

        foreach ($structural as $oc) {
            if (!isset($closure[$oc->oid])) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return array<string, true> OIDs of the class and its transitive superclasses
     */
    private function superclassClosure(ObjectClass $oc): array
    {
        $closure = [];
        $queue = [$oc];

        while ($queue !== []) {
            $current = array_shift($queue);
            if (isset($closure[$current->oid])) {
                continue;
            }

            $closure[$current->oid] = true;
            foreach ($current->superClassOids as $superOid) {
                $super = $this->schema->getObjectClass($superOid);
                if ($super !== null) {
                    $queue[] = $super;
                }
            }
        }

        return $closure;
    }

    /**
     * @param list<string> $must
     * @throws OperationException
     */
    private function checkRequiredAttributes(
        Entry $entry,
        array $must,
    ): void {
        $entryNames = $this->buildEntryAttrSet($entry);

        foreach ($must as $required) {
            if (isset($entryNames[$required])) {
                continue;
            }

            $this->fail(
                sprintf('Required attribute "%s" is missing.', $required),
                ResultCode::OBJECT_CLASS_VIOLATION,
                SchemaRule::RequiredAttributes,
            );
        }
    }

    /**
     * @param list<string> $must
     * @param list<string> $may
     * @throws OperationException
     */
    private function checkAllowedAttributes(
        Entry $entry,
        array $must,
        array $may,
    ): void {
        $allowed = array_flip(array_merge($must, $may));

        foreach ($entry->getAttributes() as $attr) {
            $attrType = $this->schema->getAttributeType($attr->getName());

            if ($attrType === null || $attrType->usage !== AttributeUsage::UserApplications) {
                continue;
            }

            if (isset($allowed[strtolower($attrType->names[0] ?? $attr->getName())])) {
                continue;
            }

            $this->fail(
                sprintf('Attribute "%s" is not permitted by any object class.', $attr->getName()),
                ResultCode::OBJECT_CLASS_VIOLATION,
                SchemaRule::AllowedAttributes,
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function checkSingleValuedAttributes(Entry $entry): void
    {
        foreach ($entry->getAttributes() as $attr) {
            $attrType = $this->schema->getAttributeType($attr->getName());
            if ($attrType === null || !$attrType->singleValue) {
                continue;
            }

            if (count($attr->getValues()) <= 1) {
                continue;
            }

            $this->fail(
                sprintf(
                    'Attribute "%s" is single-valued but has %d values.',
                    $attr->getName(),
                    count($attr->getValues()),
                ),
                ResultCode::CONSTRAINT_VIOLATION,
                SchemaRule::SingleValue,
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function checkValueCounts(Entry $entry): void
    {
        foreach ($entry->getAttributes() as $attr) {
            // Values held apart from the entry cost one row each, so their count is not what this bounds.
            if ($this->linked->heldApart($attr)) {
                continue;
            }
            $limit = $this->valueLimitFor($attr);
            $count = count($attr->getValues());

            if ($limit === AttributeType::EXTENSION_UNLIMITED_VALUES || $count <= $limit) {
                continue;
            }

            $this->fail(
                sprintf(
                    'Attribute "%s" holds %d values, which is beyond the limit of %d.',
                    $attr->getName(),
                    $count,
                    $limit,
                ),
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                SchemaRule::ValueLimit,
            );
        }
    }

    /**
     * Keyed case-insensitively so every spelling of a type shares one entry.
     */
    private function valueLimitFor(Attribute $attribute): int
    {
        $name = Attribute::normalizeName($attribute->getName());

        return $this->valueLimits[$name] ??= $this->schema->getAttributeType($name)?->maxValues()
            ?? $this->maxValues;
    }

    private function checkAttributeSyntaxes(Entry $entry): void
    {
        foreach ($entry->getAttributes() as $attr) {
            $this->validateValues($attr);
        }
    }

    /**
     * @throws OperationException
     */
    private function checkValuesConform(
        Attribute $attr,
        SyntaxValidatorInterface $validator,
    ): void {
        foreach ($attr->getValues() as $value) {
            if ($validator->isValid($value)) {
                continue;
            }

            $this->fail(
                sprintf(
                    'A value for attribute "%s" does not conform to its syntax.',
                    $attr->getName(),
                ),
                ResultCode::INVALID_ATTRIBUTE_SYNTAX,
                SchemaRule::AttributeSyntax,
            );
        }
    }

    /**
     * @return array<string, true>
     */
    private function buildEntryAttrSet(Entry $entry): array
    {
        $result = [];

        foreach ($entry->getAttributes() as $attr) {
            $attrType = $this->schema->getAttributeType($attr->getName());
            $result[strtolower($attrType?->names[0] ?? $attr->getName())] = true;
        }

        return $result;
    }

    /**
     * @throws SchemaViolationException
     */
    private function fail(
        string $message,
        int $code,
        SchemaRule $rule,
    ): never {
        throw new SchemaViolationException(
            $message,
            $code,
            $rule,
        );
    }
}
