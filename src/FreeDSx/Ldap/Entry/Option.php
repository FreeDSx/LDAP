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

/**
 * Represents an attribute option. Described in RFC 4512, Section 2.5.2.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Option
{
    protected const MATCH_RANGE = '/range=(\d+)-(.*)/';

    /**
     * @var string
     */
    protected $option;

    /**
     * @var string
     */
    protected $lcOption;
    
    /**
     * @param string $option
     */
    public function __construct(string $option)
    {
        $this->option = $option;
    }

    /**
     * @return bool
     */
    public function isLanguageTag(): bool
    {
        return $this->startsWith('lang-');
    }

    /**
     * @return bool
     */
    public function isRange(): bool
    {
        return $this->startsWith('range=');
    }

    /**
     * A convenience method to get the high value of a range option.
     *
     * @see https://msdn.microsoft.com/en-us/library/cc223242.aspx
     */
    public function getHighRange(): string
    {
        if (!$this->isRange()) {
            return '';
        }
        \preg_match(self::MATCH_RANGE, $this->option, $match);

        return $match[2] ?? null;
    }

    /**
     * A convenience method to get the low value of a range option.
     *
     * @see https://msdn.microsoft.com/en-us/library/cc223242.aspx
     * @return string|null
     */
    public function getLowRange(): ?string
    {
        if (!$this->isRange()) {
            return null;
        }
        \preg_match(self::MATCH_RANGE, $this->option, $match);

        return $match[1] ?? null;
    }

    /**
     * @param string $option
     * @return bool
     */
    public function startsWith(string $option): bool
    {
        if ($this->lcOption === null) {
            $this->lcOption = \strtolower($this->option);
        }
        $option = \strtolower($option);
        
        return \substr($this->lcOption, 0, \strlen($option)) === $option;
    }

    /**
     * Options are case insensitive, so use this to optimize case-insensitive checks.
     *
     * @param Option $option
     * @return bool
     */
    public function equals(Option $option): bool
    {
        if ($this->lcOption === null) {
            $this->lcOption = \strtolower($this->option);
        }
        if ($option->lcOption === null) {
            $option->lcOption = \strtolower($option->option);
        }
        
        return $this->lcOption === $option->lcOption;
    }

    /**
     * @param bool $lowercase forces the string representation to lowercase.
     * @return string
     */
    public function toString(bool $lowercase = false): string
    {
        if ($lowercase) {
            if ($this->lcOption === null) {
                $this->lcOption = \strtolower($this->option);
            }
            
            return $this->lcOption;
        }
        
        return $this->option;
    }
    
    /**
     * @return string
     */
    public function __toString()
    {
        return $this->option;
    }

    /**
     * Convenience factory method for creating a range option.
     *
     * @see https://msdn.microsoft.com/en-us/library/cc223242.aspx
     * @param string $startAt
     * @param string $endAt
     * @return Option
     */
    public static function fromRange(string $startAt, string $endAt = '*')
    {
        return new self('range=' . $startAt . '-' . $endAt);
    }
}
