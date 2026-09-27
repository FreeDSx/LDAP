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

namespace FreeDSx\Ldap\Schema;

use Closure;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\InvalidDnSyntaxException;
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Matching\NameAndOptionalUid;
use FreeDSx\Ldap\Search\Filter\AttributeValueAssertionInterface;
use FreeDSx\Ldap\Search\Filter\FilterContainerInterface;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;

use function array_map;
use function array_values;
use function explode;
use function implode;

/**
 * Spells the attribute types a DN, entry, or change names by their primary schema names, including those named inside values.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AttributeTypeSpelling
{
    public function __construct(
        private Schema $schema,
    ) {}

    /**
     * The same DN when no type is respelled, or when it does not parse and is left for a later step to refuse.
     */
    public function dn(Dn $dn): Dn
    {
        try {
            $rdns = $dn->toArray();
        } catch (InvalidDnSyntaxException|UnexpectedValueException) {
            return $dn;
        }

        $respelled = array_map(
            $this->rdn(...),
            $rdns,
        );

        if ($respelled === $rdns) {
            return $dn;
        }

        return new Dn(implode(
            ',',
            array_map(
                static fn(Rdn $rdn): string => $rdn->toString(),
                $respelled,
            ),
        ));
    }

    /**
     * The same RDN when no component's type is respelled. Values keep their escaped form.
     */
    public function rdn(Rdn $rdn): Rdn
    {
        $original = [];
        $respelled = [];

        foreach ($rdn->getAll() as $component) {
            $original[] = $component->getName() . '=' . $component->getValue();
            $respelled[] = $this->schema->canonicalAttributeName($component->getName())
                . '='
                . $component->getValue();
        }

        return $respelled === $original
            ? $rdn
            : Rdn::create(implode('+', $respelled));
    }

    /**
     * The same entry when neither its DN nor any attribute description is respelled.
     */
    public function entry(Entry $entry): Entry
    {
        $dn = $this->dn($entry->getDn());
        $attributes = array_map(
            $this->attribute(...),
            $entry->getAttributes(),
        );

        if ($dn === $entry->getDn() && $attributes === $entry->getAttributes()) {
            return $entry;
        }

        return Entry::raw(
            $dn,
            $attributes,
        );
    }

    /**
     * The same change when its attribute description is not respelled.
     */
    public function change(Change $change): Change
    {
        $attribute = $this->attribute($change->getAttribute());

        return $attribute === $change->getAttribute()
            ? $change
            : new Change(
                $change->getType(),
                $attribute,
            );
    }

    /**
     * Only the type portion of a description has other spellings, so its options carry over unchanged.
     */
    public function description(string $description): string
    {
        $parts = explode(
            ';',
            $description,
            2,
        );
        $type = $this->schema->canonicalAttributeName($parts[0]);

        return isset($parts[1])
            ? $type . ';' . $parts[1]
            : $type;
    }

    /**
     * Respells the attribute every item of the filter names, and any assertion value naming a type, in place.
     */
    public function rewriteFilter(FilterInterface $filter): void
    {
        match (true) {
            $filter instanceof FilterContainerInterface => $this->rewriteFilters($filter->get()),
            $filter instanceof NotFilter => $this->rewriteFilter($filter->get()),
            $filter instanceof MatchingRuleFilter => $this->rewriteMatchingRuleFilter($filter),
            $filter instanceof AttributeValueAssertionInterface => $this->rewriteValueAssertion($filter),
            $filter instanceof PresentFilter,
            $filter instanceof SubstringFilter => $filter->setAttribute($this->description($filter->getAttribute())),
            default => null,
        };
    }

    /**
     * @param FilterInterface[] $filters
     */
    private function rewriteFilters(array $filters): void
    {
        foreach ($filters as $filter) {
            $this->rewriteFilter($filter);
        }
    }

    /**
     * An extensible match may name no attribute, leaving its matching rule to decide the assertion.
     */
    private function rewriteMatchingRuleFilter(MatchingRuleFilter $filter): void
    {
        $attribute = $filter->getAttribute();
        $rule = $filter->getMatchingRule();

        if ($attribute !== null) {
            $filter->setAttribute($this->description($attribute));
        }

        // RFC 4512 §4.1.3: a rule's SYNTAX is its assertion syntax; without a rule it is the attribute's equality.
        $syntaxOid = $rule !== null
            ? $this->schema->getMatchingRule($rule)?->syntaxOid
            : $this->syntaxOf($attribute);

        $filter->setValue($this->assertionValue(
            $filter->getValue(),
            $syntaxOid,
        ));
    }

    private function rewriteValueAssertion(AttributeValueAssertionInterface $filter): void
    {
        $filter->setAttribute($this->description($filter->getAttribute()));
        $filter->setValue($this->assertionValue(
            $filter->getValue(),
            $this->syntaxOf($filter->getAttribute()),
        ));
    }

    /**
     * A value names an entry or a schema element by the same spellings a type has, so it is respelled the same way.
     */
    private function assertionValue(
        string $value,
        ?string $syntaxOid,
    ): string {
        $respell = $this->valueRespeller($syntaxOid);

        return $respell !== null
            ? $respell($value)
            : $value;
    }

    private function syntaxOf(?string $description): ?string
    {
        if ($description === null) {
            return null;
        }

        return $this->schema->getSyntaxOid(Attribute::normalizeName($description));
    }

    private function attribute(Attribute $attribute): Attribute
    {
        $description = $attribute->getDescription();
        $respelled = $this->description($description);
        $values = array_values($attribute->getValues());
        $respell = $this->valueRespeller($this->syntaxOf($attribute->getName()));
        $respelledValues = $respell !== null
            ? array_map(
                $respell,
                $values,
            )
            : $values;

        if ($respelled === $description && $respelledValues === $values) {
            return $attribute;
        }

        return new Attribute(
            $respelled,
            ...$respelledValues,
        );
    }

    /**
     * Null for a syntax whose values name nothing a schema defines.
     *
     * @return null|Closure(string): string
     */
    private function valueRespeller(?string $syntaxOid): ?Closure
    {
        return match ($syntaxOid) {
            SyntaxOid::OID_OID => $this->schema->canonicalObjectIdentifier(...),
            SyntaxOid::OID_DISTINGUISHED_NAME => $this->dnValue(...),
            SyntaxOid::OID_NAME_AND_OPTIONAL_UID => $this->nameAndOptionalUidValue(...),
            default => null,
        };
    }

    private function dnValue(string $value): string
    {
        $dn = new Dn($value);
        $respelled = $this->dn($dn);

        return $respelled === $dn
            ? $value
            : $respelled->toString();
    }

    /**
     * RFC 4517 §3.3.21: only the name before the optional bit string is a DN.
     */
    private function nameAndOptionalUidValue(string $value): string
    {
        $parsed = NameAndOptionalUid::parse($value);
        $name = $this->dnValue($parsed->name);

        if ($name === $parsed->name) {
            return $value;
        }

        return $parsed->uid === null
            ? $name
            : $name . '#' . $parsed->uid;
    }
}
