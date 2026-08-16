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

namespace FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Exception\InvalidDnSyntaxException;
use Stringable;

use function array_keys;
use function array_values;
use function count;
use function explode;
use function str_replace;
use function substr;
use function substr_replace;

/**
 * Represents a Relative Distinguished Name.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Rdn implements Stringable
{
    use EscapeTrait;
    use UnescapedSeparatorTrait;

    public const ESCAPE_MAP = [
        '\\' => '\\5c',
        '"' => '\\22',
        '+' => '\\2b',
        ',' => '\\2c',
        ';' => '\\3b',
        '<' => '\\3c',
        '>' => '\\3e',
    ];

    /**
     * RFC 4514 3: attributeType is a descr (RFC 4512 keystring) or a dotted numericoid whose arcs carry no leading zeros.
     */
    private const ATTRIBUTE_TYPE_PATTERN = '/^(?:[A-Za-z][A-Za-z0-9-]*|(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+)$/';

    /**
     * @var Rdn[]
     */
    private array $additional = [];

    public function __construct(
        private readonly string $name,
        private readonly string $value,
    ) {}

    public function __toString(): string
    {
        return $this->toString();
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

    /**
     * Return all potential RDNs, accounting for multivalued RDNs.
     *
     * @return list<Rdn>
     */
    public function getAll(): array
    {
        return array_values([
            $this,
            ...$this->additional,
        ]);
    }

    /**
     * Whether any component has the given attribute name (case-insensitive).
     */
    public function has(string $name): bool
    {
        return $this->getValueOf($name) !== null;
    }

    /**
     * Value of the component with the given attribute name, or null if absent (case-insensitive).
     */
    public function getValueOf(string $name): ?string
    {
        foreach ($this->getAll() as $component) {
            if (strcasecmp($component->getName(), $name) === 0) {
                return $component->getValue();
            }
        }

        return null;
    }

    /**
     * Whether this holds a comma a DN would read as an RDN separator rather than as part of a value.
     */
    public function hasUnescapedComma(): bool
    {
        return self::hasUnescaped(
            $this->toString(),
            ',',
        );
    }

    public function toString(): string
    {
        $rdn = $this->name . '=' . $this->value;

        foreach ($this->additional as $additional) {
            $rdn .= '+' . $additional->getName() . '=' . $additional->getValue();
        }

        return $rdn;
    }

    /**
     * @throws InvalidDnSyntaxException
     */
    public static function create(string $rdn): Rdn
    {
        $pieces = self::splitOnUnescaped(
            $rdn,
            '+',
        );

        // @todo Simplify this logic somehow?
        $obj = null;
        foreach ($pieces as $piece) {
            $parts = explode(
                separator: '=',
                string: $piece,
                limit: 2,
            );
            if (count($parts) !== 2) {
                throw new InvalidDnSyntaxException(sprintf(
                    'The RDN "%s" is invalid.',
                    $piece,
                ));
            }
            self::assertAttributeType($parts[0]);
            self::assertValue($parts[1]);

            if ($obj === null) {
                $obj = new self(
                    name: $parts[0],
                    value: $parts[1],
                );
            } else {
                $obj->additional[] = new self(
                    name: $parts[0],
                    value: $parts[1],
                );
            }
        }

        if ($obj === null) {
            throw new InvalidDnSyntaxException(sprintf(
                "The RDN '%s' is not valid.",
                $rdn,
            ));
        }

        return $obj;
    }

    /**
     * Unescape an RDN value, resolving both the \XX hex form and a backslash before a single character.
     */
    public static function unescape(string $value): string
    {
        return (string) preg_replace_callback(
            '/\\\\([0-9A-Fa-f]{2}|.)/s',
            static fn(array $matches): string => strlen($matches[1]) === 2
                ? pack('H*', $matches[1])
                : $matches[1],
            $value,
        );
    }

    /**
     * Escape an RDN value.
     */
    public static function escape(string $value): string
    {
        if (self::shouldNotEscape($value)) {
            return $value;
        }
        $value = str_replace(
            search: array_keys(self::ESCAPE_MAP),
            replace: array_values(self::ESCAPE_MAP),
            subject: $value,
        );

        if ($value[0] === '#' || $value[0] === ' ') {
            $value = ($value[0] === '#' ? '\23' : '\20') . substr($value, 1);
        }
        if ($value[-1] === ' ') {
            $value = substr_replace($value, '\20', -1, 1);
        }

        return self::escapeNonPrintable($value);
    }

    /**
     * @throws InvalidDnSyntaxException
     */
    private static function assertAttributeType(string $name): void
    {
        if (preg_match(self::ATTRIBUTE_TYPE_PATTERN, trim($name)) !== 1) {
            throw new InvalidDnSyntaxException(sprintf(
                'The attribute type "%s" is not valid in a DN.',
                $name,
            ));
        }
    }

    /**
     * @throws InvalidDnSyntaxException
     */
    private static function assertValue(string $value): void
    {
        // RFC 4514 3 admits no raw NUL, though the escaped \00 form stays legal.
        if (str_contains($value, "\0")) {
            throw new InvalidDnSyntaxException('An RDN value cannot hold an unescaped null byte.');
        }

        // The 2.4 hexstring form is refused: no other common LDAP implementation supports it as specified, and
        // nothing is known to emit it. May revisit if there's a legitimate use case.
        if (str_starts_with($value, '#')) {
            throw new InvalidDnSyntaxException(
                'The hexstring form of an RDN value is not supported; escape a literal "#" as \23.',
            );
        }
    }
}
