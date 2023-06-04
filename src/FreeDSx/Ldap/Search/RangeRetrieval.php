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

namespace FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Option;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\LdapClient;
use Stringable;

/**
 * Provides simple helper APIs for retrieving ranged results for an entry attribute.
 *
 * @see https://docs.microsoft.com/en-us/windows/desktop/adsi/attribute-range-retrieval
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class RangeRetrieval
{
    private LdapClient $client;

    public function __construct(LdapClient $client)
    {
        $this->client = $client;
    }

    /**
     * Get a specific ranged attribute by name from an entry. If it does not exist it will return null.
     */
    public function getRanged(
        Entry $entry,
        Attribute|string $attribute
    ): ?Attribute {
        $attribute = $attribute instanceof Attribute
            ? new Attribute($attribute->getName())
            : new Attribute($attribute);

        foreach ($this->getAllRanged($entry) as $rangedAttribute) {
            if ($rangedAttribute->equals($attribute)) {
                return $rangedAttribute;
            }
        }

        return null;
    }

    /**
     * Get all ranged attributes as an array from a entry.
     *
     * @return Attribute[]
     */
    public function getAllRanged(Entry $entry): array
    {
        $ranged = [];

        foreach ($entry->getAttributes() as $attribute) {
            if (!$attribute->hasOptions()) {
                continue;
            }
            foreach ($attribute->getOptions()->toArray() as $option) {
                if ($option->isRange()) {
                    $ranged[] = $attribute;
                    break;
                }
            }
        }

        return $ranged;
    }

    /**
     * A simple check to determine if an entry contains any ranged attributes. Optionally pass an attribute
     */
    public function hasRanged(
        Entry $entry,
        Attribute|string $attribute = null
    ): bool {
        return $attribute !== null
            ? (bool) $this->getRanged($entry, $attribute)
            : (bool) $this->getAllRanged($entry);
    }

    /**
     * Check if an attribute has more range values that can be queried.
     */
    public function hasMoreValues(Attribute $attribute): bool
    {
        if (($range = $this->getRangeOption($attribute)) === null) {
            return false;
        }

        return $range->getHighRange() !== '*';
    }

    /**
     * Given a specific Entry/DN and an attribute, get the next set of ranged values available. Optionally pass a third
     * parameter to control how many values to grab next.
     *
     * @throws OperationException
     */
    public function getMoreValues(
        Stringable|Entry|Dn|string $entry,
        Attribute $attribute,
        string|int $amount = '*'
    ): Attribute {
        if (($range = $this->getRangeOption($attribute)) === null || !$this->hasMoreValues($attribute)) {
            return new Attribute($attribute->getName());
        }
        if ($amount !== '*') {
            $amount = (int) $amount + (int) $range->getHighRange();
        }
        $attrReq = new Attribute($attribute->getName());
        $startAt = (int) $range->getHighRange() + 1;
        $attrReq->getOptions()->set(Option::fromRange((string) $startAt, (string) $amount));
        $result = $this->client->readOrFail(
            (string) $entry,
            [$attrReq]
        );

        $attrResult = $result->get($attribute->getName());
        if ($attrResult === null) {
            throw new RuntimeException(sprintf(
                'The attribute %s was not returned from LDAP',
                $attribute->getName()
            ));
        }
        if ($this->getRangeOption($attrResult) === null) {
            throw new RuntimeException(sprintf(
                'No ranged option received for attribute "%s" on "%s".',
                $attribute->getName(),
                $result->getDn()->toString()
            ));
        }

        return $attrResult;
    }

    /**
     * Given a specific entry and attribute, range retrieve all values of the attribute.
     *
     * @throws OperationException
     */
    public function getAllValues(
        Stringable|Entry|Dn|string $entry,
        Attribute|string $attribute,
    ): Attribute {
        $attrResult = $attribute instanceof Attribute
            ? new Attribute($attribute->getName())
            : new Attribute($attribute);
        $attrResult->getOptions()
            ->set(Option::fromRange('0'));

        $entry = $this->client->readOrFail(
            (string) $entry,
            [$attrResult]
        );
        $attribute = $this->getRanged(
            $entry,
            $attrResult
        );
        if ($attribute === null) {
            throw new RuntimeException(sprintf(
                'No ranged result received for "%s" on entry "%s".',
                $attrResult->getName(),
                $entry->getDn()->toString()
            ));
        }

        $attrResult->add(...$attribute->getValues());
        while ($this->hasMoreValues($attribute)) {
            $attribute = $this->getMoreValues($entry, $attribute);
            $attrResult->add(...$attribute->getValues());
        }

        return $attrResult;
    }

    private function getRangeOption(Attribute $attribute): ?Option
    {
        /** @var Option $option */
        foreach ($attribute->getOptions() as $option) {
            if ($option->isRange()) {
                return $option;
            }
        }

        return null;
    }
}
