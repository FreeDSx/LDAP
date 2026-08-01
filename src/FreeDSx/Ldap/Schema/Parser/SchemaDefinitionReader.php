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

namespace FreeDSx\Ldap\Schema\Parser;

use FreeDSx\Ldap\Exception\SchemaParseException;

use function chr;
use function ctype_xdigit;
use function hexdec;
use function preg_match;
use function sprintf;
use function str_contains;
use function strlen;
use function strpos;
use function substr;

/**
 * A character cursor over a single RFC 4512 description string, exposing the token primitives a parser needs.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SchemaDefinitionReader
{
    private const WHITESPACE = " \t\r\n";

    /**
     * Characters that terminate a bare (unquoted) token.
     */
    private const DELIMITERS = " \t\r\n()$'";

    private const NUMERIC_OID = '/^\d+(?:\.\d+)+$/';

    private int $offset = 0;

    private readonly int $length;

    public function __construct(private readonly string $definition)
    {
        $this->length = strlen($definition);
    }

    public function atEnd(): bool
    {
        $this->skipWhitespace();

        return $this->offset >= $this->length;
    }

    /**
     * The current character offset, used to assert a parse loop is making progress.
     */
    public function offset(): int
    {
        return $this->offset;
    }

    /**
     * Whether the next non-whitespace character is the one given, without consuming it.
     */
    public function isNext(string $char): bool
    {
        $this->skipWhitespace();

        return $this->offset < $this->length
            && $this->definition[$this->offset] === $char;
    }

    /**
     * Consumes the given character when it is next, reporting whether it was there.
     */
    public function consumeIf(string $char): bool
    {
        if (!$this->isNext($char)) {
            return false;
        }

        $this->offset++;

        return true;
    }

    /**
     * @throws SchemaParseException
     */
    public function expect(string $char): void
    {
        if (!$this->consumeIf($char)) {
            $this->error(sprintf(
                'Expected "%s"',
                $char,
            ));
        }
    }

    /**
     * Reads an unquoted token: a keyword, an OID, a descriptor, or a bare extension value.
     *
     * @throws SchemaParseException
     */
    public function readBareToken(): string
    {
        $this->skipWhitespace();
        $start = $this->offset;

        while (
            $this->offset < $this->length
            && !str_contains(self::DELIMITERS, $this->definition[$this->offset])
        ) {
            $this->offset++;
        }

        if ($this->offset === $start) {
            $this->error('Expected a value');
        }

        return substr(
            $this->definition,
            $start,
            $this->offset - $start,
        );
    }

    /**
     * Reads an OID, discarding any {n} length bound since the definition objects carry no length.
     *
     * @throws SchemaParseException
     */
    public function readOid(): string
    {
        $oid = $this->readBareToken();
        $brace = strpos($oid, '{');

        return $brace === false
            ? $oid
            : substr(
                $oid,
                0,
                $brace,
            );
    }

    /**
     * Reads an OID that must be in numeric dotted form.
     *
     * @throws SchemaParseException
     */
    public function readNumericOid(): string
    {
        $at = $this->offset;
        $oid = $this->readOid();

        if (preg_match(self::NUMERIC_OID, $oid) !== 1) {
            $this->error(
                sprintf(
                    'Expected a numeric OID, got "%s"',
                    $oid,
                ),
                $at,
            );
        }

        return $oid;
    }

    /**
     * Reads a single OID or a parenthesized list of them, which RFC 4512 §1.4 separates by a dollar sign.
     *
     * @return list<string>
     * @throws SchemaParseException
     */
    public function readOids(): array
    {
        if (!$this->consumeIf('(')) {
            return [$this->readOid()];
        }

        $oids = $this->readParenthesizedList($this->readOid(...));

        if ($oids === []) {
            $this->error('Expected at least one OID');
        }

        return $oids;
    }

    /**
     * Reads a single quoted or bare value, or a parenthesized list of them, which RFC 4512 §1.4 separates by space.
     *
     * @return list<string>
     * @throws SchemaParseException
     */
    public function readQdstrings(): array
    {
        if (!$this->consumeIf('(')) {
            return [$this->readQdstring()];
        }

        return $this->readParenthesizedList($this->readQdstring(...));
    }

    /**
     * Reads one quoted string, unescaping it; a bare token is accepted since not every server quotes values.
     *
     * @throws SchemaParseException
     */
    public function readQdstring(): string
    {
        if (!$this->consumeIf("'")) {
            return $this->readBareToken();
        }

        $value = '';

        while ($this->offset < $this->length) {
            $char = $this->definition[$this->offset];

            if ($char === "'") {
                $this->offset++;

                return $value;
            }

            $value .= $char === '\\'
                ? $this->readEscape()
                : $this->readLiteral();
        }

        $this->error('Unterminated quoted string');
    }

    /**
     * @throws SchemaParseException
     */
    public function error(
        string $message,
        ?int $at = null,
    ): never {
        throw new SchemaParseException(
            $message,
            $this->definition,
            $at ?? $this->offset,
        );
    }

    /**
     * Reads items up to the closing paren; a dollar separator is optional so both list forms are accepted.
     *
     * @param callable(): string $readItem
     * @return list<string>
     * @throws SchemaParseException
     */
    private function readParenthesizedList(callable $readItem): array
    {
        $items = [];

        while (!$this->isNext(')')) {
            if ($this->atEnd()) {
                $this->error('Unterminated list, expected ")"');
            }

            $at = $this->offset;
            $items[] = $readItem();
            $this->consumeIf('$');

            if ($this->offset === $at) {
                $this->error('Expected a list item');
            }
        }

        $this->expect(')');

        return $items;
    }

    /**
     * Consumes a backslash escape: a hex pair per RFC 4512, otherwise the following character literally.
     *
     * @throws SchemaParseException
     */
    private function readEscape(): string
    {
        $hex = substr(
            $this->definition,
            $this->offset + 1,
            2,
        );

        if (strlen($hex) === 2 && ctype_xdigit($hex)) {
            $this->offset += 3;

            return chr(((int) hexdec($hex)) & 0xFF);
        }

        if ($this->offset + 1 >= $this->length) {
            $this->error('Unterminated escape sequence');
        }

        $this->offset += 2;

        return $this->definition[$this->offset - 1];
    }

    private function readLiteral(): string
    {
        $char = $this->definition[$this->offset];
        $this->offset++;

        return $char;
    }

    private function skipWhitespace(): void
    {
        while ($this->offset < $this->length && str_contains(self::WHITESPACE, $this->definition[$this->offset])) {
            $this->offset++;
        }
    }
}
