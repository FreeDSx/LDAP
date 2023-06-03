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

namespace FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\Factory\FilterFactory;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use function array_map;

/**
 * A Search Request. RFC 4511, 4.5.1.
 *
 * SearchRequest ::= [APPLICATION 3] SEQUENCE {
 *     baseObject      LDAPDN,
 *     scope           ENUMERATED {
 *         baseObject              (0),
 *         singleLevel             (1),
 *         wholeSubtree            (2),
 *         ...  },
 *     derefAliases    ENUMERATED {
 *         neverDerefAliases       (0),
 *         derefInSearching        (1),
 *         derefFindingBaseObj     (2),
 *         derefAlways             (3) },
 *     sizeLimit       INTEGER (0 ..  maxInt),
 *     timeLimit       INTEGER (0 ..  maxInt),
 *     typesOnly       BOOLEAN,
 *     filter          Filter,
 *     attributes      AttributeSelection }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SearchRequest implements RequestInterface
{
    /**
     * Searches a scope of a single object (IE. a specific DN)
     */
    public const SCOPE_BASE_OBJECT = 0;

    /**
     * Searches one level under a specific DN (ie. like a non-recursive directory listing).
     */
    public const SCOPE_SINGLE_LEVEL = 1;

    /**
     * Searches a complete subtree under a DN (ie. like a recursive directory listing).
     */
    public const SCOPE_WHOLE_SUBTREE = 2;

    /**
     * Never dereference aliases.
     */
    public const DEREF_NEVER = 0;

    public const DEREF_IN_SEARCHING = 1;

    /**
     * Dereference aliases when finding the base object only.
     */
    public const DEREF_FINDING_BASE_OBJECT = 2;

    /**
     * Always dereference aliases.
     */
    public const DEREF_ALWAYS = 3;

    protected const APP_TAG = 3;

    private ?Dn $baseDn = null;

    private int $scope = self::SCOPE_WHOLE_SUBTREE;

    private int $derefAliases = self::DEREF_NEVER;

    private int $sizeLimit = 0;

    private int $timeLimit = 0;

    private bool $attributesOnly = false;

    private FilterInterface $filter;

    /**
     * @var Attribute[]
     */
    private array $attributes = [];

    public function __construct(
        FilterInterface $filter,
        Attribute|string ...$attributes
    ) {
        $this->filter = $filter;
        $this->setAttributes(...$attributes);
    }

    /**
     * Alias to setAttributes. Convenience for a more fluent method call.
     */
    public function select(Attribute|string ...$attributes): self
    {
        return $this->setAttributes(...$attributes);
    }

    /**
     * Alias to setBaseDn. Convenience for a more fluent method call.
     */
    public function base(string|Dn|null $dn): self
    {
        return $this->setBaseDn($dn);
    }

    /**
     * Set the search scope for all children underneath the base DN.
     */
    public function useSubtreeScope(): self
    {
        $this->scope = self::SCOPE_WHOLE_SUBTREE;

        return $this;
    }

    /**
     * Set the search scope to the base DN object only.
     */
    public function useBaseScope(): self
    {
        $this->scope = self::SCOPE_BASE_OBJECT;

        return $this;
    }

    /**
     * Set the search scope to a single level listing from the base DN.
     */
    public function useSingleLevelScope(): self
    {
        $this->scope = self::SCOPE_SINGLE_LEVEL;

        return $this;
    }

    /**
     * Alias to setSizeLimit. Convenience for a more fluent method call.
     */
    public function sizeLimit(int $size): self
    {
        return $this->setSizeLimit($size);
    }

    /**
     * Alias to setTimeLimit. Convenience for a more fluent method call.
     */
    public function timeLimit(int $time): self
    {
        return $this->setTimeLimit($time);
    }

    /**
     * @return Attribute[]
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function setAttributes(Attribute|string ...$attributes): self
    {
        $attr = [];
        foreach ($attributes as $attribute) {
            $attr[] = $attribute instanceof Attribute ? $attribute : new Attribute($attribute);
        }
        $this->attributes = $attr;

        return $this;
    }

    public function getBaseDn(): ?Dn
    {
        return $this->baseDn;
    }

    public function setBaseDn(string|Dn|null $baseDn): self
    {
        if ($baseDn !== null) {
            $baseDn = $baseDn instanceof Dn ? $baseDn : new Dn($baseDn);
        }
        $this->baseDn = $baseDn;

        return $this;
    }

    public function getScope(): int
    {
        return $this->scope;
    }

    public function setScope(int $scope): self
    {
        $this->scope = $scope;

        return $this;
    }

    public function getDereferenceAliases(): int
    {
        return $this->derefAliases;
    }

    public function setDereferenceAliases(int $derefAliases): self
    {
        $this->derefAliases = $derefAliases;

        return $this;
    }

    public function getSizeLimit(): int
    {
        return $this->sizeLimit;
    }

    public function setSizeLimit(int $sizeLimit): self
    {
        $this->sizeLimit = $sizeLimit;

        return $this;
    }

    public function getTimeLimit(): int
    {
        return $this->timeLimit;
    }

    public function setTimeLimit(int $timeLimit): self
    {
        $this->timeLimit = $timeLimit;

        return $this;
    }

    public function getAttributesOnly(): bool
    {
        return $this->attributesOnly;
    }

    public function setAttributesOnly(bool $attributesOnly): self
    {
        $this->attributesOnly = $attributesOnly;

        return $this;
    }

    public function getFilter(): FilterInterface
    {
        return $this->filter;
    }

    public function setFilter(FilterInterface $filter): self
    {
        $this->filter = $filter;

        return $this;
    }

    /**
     * {@inheritDoc}
     *
     * @throws RuntimeException
     */
    public static function fromAsn1(AbstractType $type): self
    {
        if (!($type instanceof SequenceType && count($type) === 8)) {
            throw new ProtocolException('The search request is malformed');
        }
        $baseDn = $type->getChild(0);
        $scope = $type->getChild(1);
        $deref = $type->getChild(2);
        $sizeLimit = $type->getChild(3);
        $timeLimit = $type->getChild(4);
        $typesOnly = $type->getChild(5);
        $attributes = $type->getChild(7);

        $filter = $type->getChild(6);
        if ($filter === null) {
            throw new ProtocolException('The search request is malformed.');
        }
        $filter = FilterFactory::get($filter);

        if (
            !($baseDn instanceof OctetStringType
            && $scope instanceof EnumeratedType
            && $deref instanceof EnumeratedType
            && $sizeLimit instanceof IntegerType
            && $timeLimit instanceof IntegerType
            && $typesOnly instanceof BooleanType
            && $attributes instanceof SequenceType)
        ) {
            throw new ProtocolException('The search request is malformed');
        }

        $attrList = [];
        foreach ($attributes->getChildren() as $attribute) {
            if (!$attribute instanceof OctetStringType) {
                throw new ProtocolException('The search request is malformed.');
            }
            $attrList[] = new Attribute($attribute->getValue());
        }

        $search = new self($filter, ...$attrList);
        $search->setScope($scope->getValue());
        $search->setBaseDn($baseDn->getValue());
        $search->setDereferenceAliases($deref->getValue());
        $search->setSizeLimit($sizeLimit->getValue());
        $search->setTimeLimit($timeLimit->getValue());
        $search->setAttributesOnly($typesOnly->getValue());

        return $search;
    }

    /**
     * @throws RuntimeException
     */
    public function toAsn1(): AbstractType
    {
        if ($this->baseDn === null) {
            throw new RuntimeException('The search baseDn cannot be empty.');
        }

        return Asn1::application(self::APP_TAG, Asn1::sequence(
            Asn1::octetString($this->baseDn->toString()),
            Asn1::enumerated($this->scope),
            Asn1::enumerated($this->derefAliases),
            Asn1::integer($this->sizeLimit),
            Asn1::integer($this->timeLimit),
            Asn1::boolean($this->attributesOnly),
            $this->filter->toAsn1(),
            Asn1::sequenceOf(...array_map(function (Attribute $attr) {
                return Asn1::octetString($attr->getDescription());
            }, $this->attributes))
        ));
    }
}
