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

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use function array_keys;
use function array_values;
use function count;
use function explode;
use function preg_split;
use function str_replace;
use function substr;
use function substr_replace;

/**
 * Represents a Relative Distinguished Name.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Rdn
{
    use EscapeTrait;

    public const ESCAPE_MAP = [
        '\\' => '\\5c',
        '"' => '\\22',
        '+' => '\\2b',
        ',' => '\\2c',
        ';' => '\\3b',
        '<' => '\\3c',
        '>' => '\\3e',
    ];

    private string $name;

    private string $value;

    /**
     * @var Rdn[]
     */
    protected array $additional = [];

    public function __construct(
        string $name,
        string $value
    ) {
        $this->name = $name;
        $this->value = $value;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function isMultivalued(): bool
    {
        return count($this->additional) !== 0;
    }

    public function toString(): string
    {
        $rdn = $this->name . '=' . $this->value;

        foreach ($this->additional as $additional) {
            $rdn .= '+' . $additional->getName() . '=' . $additional->getValue();
        }

        return $rdn;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function create(string $rdn): Rdn
    {
        $pieces = preg_split('/(?<!\\\\)\+/', $rdn);
        if ($pieces === false) {
            throw new InvalidArgumentException(sprintf('The RDN "%s" is invalid.', $rdn));
        }

        // @todo Simplify this logic somehow?
        $obj = null;
        foreach ($pieces as $piece) {
            $parts = explode('=', $piece, 2);
            if (count($parts) !== 2) {
                throw new InvalidArgumentException(sprintf('The RDN "%s" is invalid.', $piece));
            }
            if ($obj === null) {
                $obj = new self($parts[0], $parts[1]);
            } else {
                /** @var Rdn $obj */
                $obj->additional[] = new self($parts[0], $parts[1]);
            }
        }

        if ($obj === null) {
            throw new InvalidArgumentException(sprintf("The RDN '%s' is not valid.", $rdn));
        }

        return $obj;
    }

    /**
     * Escape an RDN value.
     */
    public static function escape(string $value): string
    {
        if (self::shouldNotEscape($value)) {
            return $value;
        }
        $value = str_replace(array_keys(self::ESCAPE_MAP), array_values(self::ESCAPE_MAP), $value);

        if ($value[0] === '#' || $value[0] === ' ') {
            $value = ($value[0] === '#' ? '\23' : '\20') . substr($value, 1);
        }
        if ($value[-1] === ' ') {
            $value = substr_replace($value, '\20', -1, 1);
        }

        return self::escapeNonPrintable($value);
    }
}
