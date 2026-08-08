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

namespace FreeDSx\Ldap\Server\Subentry;

use FreeDSx\Ldap\Exception\SubtreeSpecificationParseException;

use function ctype_digit;
use function sprintf;
use function str_contains;
use function strlen;
use function substr;

/**
 * A character cursor over a GSER subtree specification value, exposing the token primitives a parser needs.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SubtreeSpecificationReader
{
    private const WHITESPACE = " \t\r\n";

    /**
     * Characters that terminate a bare (unquoted) token.
     */
    private const DELIMITERS = " \t\r\n{},:\"";

    private int $offset = 0;

    private readonly int $length;

    public function __construct(private readonly string $specification)
    {
        $this->length = strlen($specification);
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
            && $this->specification[$this->offset] === $char;
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
     * @throws SubtreeSpecificationParseException
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
     * Reads an unquoted token: a component identifier, a refinement keyword, or an object class name.
     *
     * @throws SubtreeSpecificationParseException
     */
    public function readBareToken(): string
    {
        $this->skipWhitespace();
        $start = $this->offset;

        while ($this->atTokenCharacter()) {
            $this->offset++;
        }

        if ($this->offset === $start) {
            $this->error('Expected a value');
        }

        return substr(
            $this->specification,
            $start,
            $this->offset - $start,
        );
    }

    /**
     * Reads a GSER character string, in which a doubled quote stands for one literal quote.
     *
     * @throws SubtreeSpecificationParseException
     */
    public function readString(): string
    {
        $at = $this->offset;

        if (!$this->consumeIf('"')) {
            $this->error(
                'Expected a quoted string',
                $at,
            );
        }

        $value = '';

        while ($this->offset < $this->length) {
            $char = $this->specification[$this->offset];
            $this->offset++;

            if ($char !== '"') {
                $value .= $char;

                continue;
            }

            if ($this->isNextLiteralQuote()) {
                $value .= '"';
                $this->offset++;

                continue;
            }

            return $value;
        }

        $this->error(
            'Unterminated quoted string',
            $at,
        );
    }

    /**
     * @throws SubtreeSpecificationParseException
     */
    public function readInteger(): int
    {
        $at = $this->offset;
        $token = $this->readBareToken();

        if (!ctype_digit($token)) {
            $this->error(
                sprintf(
                    'Expected a non-negative integer, got "%s"',
                    $token,
                ),
                $at,
            );
        }

        return (int) $token;
    }

    /**
     * @throws SubtreeSpecificationParseException
     */
    public function error(
        string $message,
        ?int $at = null,
    ): never {
        throw new SubtreeSpecificationParseException(
            $message,
            $this->specification,
            $at ?? $this->offset,
        );
    }

    /**
     * Whether the cursor sits on a character that a bare token may contain.
     */
    private function atTokenCharacter(): bool
    {
        return $this->offset < $this->length
            && !str_contains(self::DELIMITERS, $this->specification[$this->offset]);
    }

    /**
     * Whether the cursor sits on the second quote of a doubled pair, which stands for one literal quote.
     */
    private function isNextLiteralQuote(): bool
    {
        return $this->offset < $this->length
            && $this->specification[$this->offset] === '"';
    }

    private function atWhitespace(): bool
    {
        return $this->offset < $this->length
            && str_contains(self::WHITESPACE, $this->specification[$this->offset]);
    }

    private function skipWhitespace(): void
    {
        while ($this->atWhitespace()) {
            $this->offset++;
        }
    }
}
