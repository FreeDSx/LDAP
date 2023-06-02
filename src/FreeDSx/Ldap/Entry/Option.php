<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Entry;

use Stringable;
use function preg_match;
use function strlen;
use function strtolower;
use function substr;

/**
 * Represents an attribute option. Described in RFC 4512, Section 2.5.2.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Option implements Stringable
{
    protected const MATCH_RANGE = '/range=(\d+)-(.*)/';

    private string $option;

    private ?string $lcOption = null;

    public function __construct(string $option)
    {
        $this->option = $option;
    }

    public function isLanguageTag(): bool
    {
        return $this->startsWith('lang-');
    }

    public function isRange(): bool
    {
        return $this->startsWith('range=');
    }

    /**
     * A convenience method to get the high value of a range option.
     *
     * @see https://msdn.microsoft.com/en-us/library/cc223242.aspx
     */
    public function getHighRange(): ?string
    {
        if (!$this->isRange()) {
            return '';
        }
        preg_match(self::MATCH_RANGE, $this->option, $match);

        return $match[2] ?? null;
    }

    /**
     * A convenience method to get the low value of a range option.
     *
     * @see https://msdn.microsoft.com/en-us/library/cc223242.aspx
     */
    public function getLowRange(): ?string
    {
        if (!$this->isRange()) {
            return null;
        }
        preg_match(self::MATCH_RANGE, $this->option, $match);

        return $match[1] ?? null;
    }

    public function startsWith(string $option): bool
    {
        if ($this->lcOption === null) {
            $this->lcOption = strtolower($this->option);
        }
        $option = strtolower($option);

        return str_starts_with($this->lcOption, $option);
    }

    /**
     * Options are case-insensitive, so use this to optimize case-insensitive checks.
     */
    public function equals(Option $option): bool
    {
        if ($this->lcOption === null) {
            $this->lcOption = strtolower($this->option);
        }
        if ($option->lcOption === null) {
            $option->lcOption = strtolower($option->option);
        }

        return $this->lcOption === $option->lcOption;
    }

    /**
     * @param bool $lowercase forces the string representation to lowercase.
     */
    public function toString(bool $lowercase = false): string
    {
        if ($lowercase) {
            if ($this->lcOption === null) {
                $this->lcOption = strtolower($this->option);
            }

            return $this->lcOption;
        }

        return $this->option;
    }

    public function __toString(): string
    {
        return $this->option;
    }

    /**
     * Convenience factory method for creating a range option.
     *
     * @see https://msdn.microsoft.com/en-us/library/cc223242.aspx
     */
    public static function fromRange(
        string $startAt,
        string $endAt = '*'
    ): self {
        return new self('range=' . $startAt . '-' . $endAt);
    }
}
