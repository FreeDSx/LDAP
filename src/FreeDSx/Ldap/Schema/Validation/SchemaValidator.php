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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Schema\Validation\Syntax\SyntaxValidatorInterface;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;

/**
 * Validates entries against the schema for add and modify operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SchemaValidator
{
    private const EXTENSIBLE_OBJECT = 'extensibleObject';

    private readonly AttributeSyntaxResolver $syntaxResolver;

    public function __construct(
        private readonly Schema $schema,
        private readonly SchemaValidationMode $mode,
    ) {
        $this->syntaxResolver = new AttributeSyntaxResolver($schema);
    }

    public function mode(): SchemaValidationMode
    {
        return $this->mode;
    }

    /**
     * Validates an entry before it is added to storage.
     *
     * @param bool $isSystem Skip the NO-USER-MODIFICATION check for server-initiated writes.
     * @throws OperationException
     */
    public function validateAdd(
        Entry $entry,
        bool $isSystem = false,
    ): void {
        if ($this->mode === SchemaValidationMode::Off) {
            return;
        }
        // Checked first, since a caller relaxing an earlier violation would otherwise stop validation before this.
        $this->checkAttributeSyntaxes($entry);

        if (!$isSystem) {
            $this->checkNoUserModificationInEntry($entry);
        }
        $this->checkDistinctAttributeDescriptions($entry);
        $this->checkNoEquivalentValues($entry);
        $this->validateStructure($entry);
    }

    /**
     * Validates the changes and resulting entry from an update operation.
     *
     * @param bool $isSystem Skip the NO-USER-MODIFICATION check for server-initiated writes.
     * @throws OperationException
     */
    public function validateModify(
        UpdateCommand $command,
        Entry $result,
        bool $isSystem = false,
    ): void {
        if ($this->mode === SchemaValidationMode::Off) {
            return;
        }

        // Checked first, since a caller relaxing an earlier violation would otherwise stop validation before this.
        $this->checkAttributeSyntaxes($result);

        if (!$isSystem) {
            $this->checkNoUserModificationInChanges($command->changes);
        }
        $this->checkNoEquivalentValues($result);
        $this->checkStructuralClassUnchanged($result);
        $this->validateStructure($result);
    }

    /**
     * Validates the entry resulting from a modifyDn, where the new RDN adds values and the old one may remove them.
     *
     * @param bool $isSystem Skip the NO-USER-MODIFICATION check for server-initiated writes.
     * @throws OperationException
     */
    public function validateModifyDn(
        Entry $result,
        Rdn $newRdn,
        bool $isSystem = false,
    ): void {
        if ($this->mode === SchemaValidationMode::Off) {
            return;
        }

        // Checked first, since a caller relaxing an earlier violation would otherwise stop validation before this.
        $this->checkAttributeSyntaxes($result);
        if (!$isSystem) {
            $this->checkNoUserModificationInRdn($newRdn);
        }

        $this->checkNoEquivalentValues($result);
        $this->validateStructure($result);
    }

    /**
     * The new RDN is client-supplied, so the values it puts on the entry face the same restriction as a modify.
     *
     * @throws OperationException
     */
    private function checkNoUserModificationInRdn(Rdn $rdn): void
    {
        foreach ($rdn->getAll() as $component) {
            $attrType = $this->schema->getAttributeType($component->getName());

            if ($attrType === null || !$attrType->noUserModification) {
                continue;
            }

            $this->fail(
                sprintf('Attribute "%s" cannot be set by users.', $component->getName()),
                ResultCode::CONSTRAINT_VIOLATION,
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
     * @throws OperationException
     */
    private function validateStructure(Entry $entry): void
    {
        $objectClasses = $this->collectObjectClasses($entry);

        $this->checkStructuralClass($entry, $objectClasses);
        $chain = new ObjectClassChain($this->schema, $objectClasses);
        $this->checkRequiredAttributes($entry, $chain->must);
        $this->checkAttributeTypesAreDefined($entry);

        // RFC 4512 §4.3 lets extensibleObject hold any user attribute, so only the MAY list is waived; the
        // structural class, the MUST attributes, and the types themselves still apply.
        if (!$this->hasExtensibleObject($entry)) {
            $this->checkAllowedAttributes($entry, $chain->must, $chain->may);
        }

        $this->checkSingleValuedAttributes($entry);
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
                );
            }

            $seen[$description] = true;
        }
    }

    /**
     * RFC 4511 §4.1.7: no two of an attribute's values may be equivalent.
     *
     * @throws OperationException
     */
    private function checkNoEquivalentValues(Entry $entry): void
    {
        foreach ($entry->getAttributes() as $attr) {
            if (!$this->hasEquivalentValues($attr)) {
                continue;
            }

            $this->fail(
                sprintf('Attribute "%s" is supplied an equivalent value more than once.', $attr->getDescription()),
                ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
            );
        }
    }

    /**
     * Equivalence is the type's equality rule rather than a normalized key, so each value is put to the ones before it.
     */
    private function hasEquivalentValues(Attribute $attr): bool
    {
        $comparator = $this->equalityComparatorFor($attr->getName());
        $seen = [];

        foreach ($attr->getValues() as $value) {
            if ($this->equalsAny($comparator, $seen, $value)) {
                return true;
            }

            $seen[] = $value;
        }

        return false;
    }

    /**
     * @param list<string> $values
     */
    private function equalsAny(
        MatchingRuleComparatorInterface $comparator,
        array $values,
        string $candidate,
    ): bool {
        foreach ($values as $value) {
            if ($comparator->equals($value, $candidate)) {
                return true;
            }
        }

        return false;
    }

    private function equalityComparatorFor(string $attribute): MatchingRuleComparatorInterface
    {
        $equalityOid = $this->schema->getAttributeType($attribute)?->equalityOid;
        $comparator = $equalityOid !== null
            ? $this->schema->getComparator($equalityOid)
            : null;

        return $comparator ?? new CaseIgnoreComparator();
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
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function checkAttributeSyntaxes(Entry $entry): void
    {
        foreach ($entry->getAttributes() as $attr) {
            $attrType = $this->schema->getAttributeType($attr->getName());
            if ($attrType === null) {
                continue;
            }

            $validator = $this->syntaxResolver->validatorFor($attrType);
            if ($validator === null) {
                continue;
            }

            $this->checkValuesConform(
                $attr,
                $validator,
            );
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
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function checkNoUserModificationInEntry(Entry $entry): void
    {
        foreach ($entry->getAttributes() as $attr) {
            $attrType = $this->schema->getAttributeType($attr->getName());
            if ($attrType === null || !$attrType->noUserModification) {
                continue;
            }

            $this->fail(
                sprintf('Attribute "%s" cannot be set by users.', $attr->getName()),
                ResultCode::CONSTRAINT_VIOLATION,
            );
        }
    }

    /**
     * @param Change[] $changes
     * @throws OperationException
     */
    private function checkNoUserModificationInChanges(array $changes): void
    {
        foreach ($changes as $change) {
            $attrType = $this->schema->getAttributeType($change->getAttribute()->getName());
            if ($attrType === null || !$attrType->noUserModification) {
                continue;
            }

            $this->fail(
                sprintf('Attribute "%s" cannot be modified by users.', $change->getAttribute()->getName()),
                ResultCode::CONSTRAINT_VIOLATION,
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
     * @throws OperationException
     */
    private function fail(
        string $message,
        int $code,
    ): never {
        throw new OperationException(
            $message,
            $code,
        );
    }
}
