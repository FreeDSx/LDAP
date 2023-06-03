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

namespace FreeDSx\Ldap\Control\Sorting;

/**
 * Represents a server side sorting request SortKey.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SortKey
{
    private string $attribute;

    private ?string $orderingRule;

    private bool $useReverseOrder;

    public function __construct(
        string $attribute,
        bool $useReverseOrder = false,
        ?string $orderingRule = null
    ) {
        $this->attribute = $attribute;
        $this->orderingRule = $orderingRule;
        $this->useReverseOrder = $useReverseOrder;
    }

    public function getAttribute(): string
    {
        return $this->attribute;
    }

    public function setAttribute(string $attribute): self
    {
        $this->attribute = $attribute;

        return $this;
    }

    public function getOrderingRule(): ?string
    {
        return $this->orderingRule;
    }

    public function setOrderingRule(?string $orderingRule): self
    {
        $this->orderingRule = $orderingRule;

        return $this;
    }

    public function getUseReverseOrder(): bool
    {
        return $this->useReverseOrder;
    }

    public function setUseReverseOrder(bool $useReverseOrder): self
    {
        $this->useReverseOrder = $useReverseOrder;

        return $this;
    }

    /**
     * Create an ascending sort key.
     */
    public static function ascending(
        string $attribute,
        ?string $matchRule = null
    ): self {
        return new self(
            $attribute,
            false,
            $matchRule,
        );
    }

    /**
     * Create a descending sort key.
     */
    public static function descending(
        string $attribute,
        ?string $matchRule = null
    ): self {
        return new self(
            $attribute,
            true,
            $matchRule,
        );
    }
}
