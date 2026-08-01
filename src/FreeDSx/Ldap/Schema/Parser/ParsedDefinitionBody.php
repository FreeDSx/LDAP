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

use function sprintf;
use function str_starts_with;
use function strtoupper;

/**
 * The keyword/value pairs read from the body of a schema definition, between the OID and the closing paren.
 *
 * @internal
 */
class ParsedDefinitionBody
{
    /**
     * Vendor extensions are any keyword with this prefix, per RFC 4512 §4.1.
     */
    private const EXTENSION_PREFIX = 'X-';

    /**
     * @var array<string, string>
     */
    private array $strings = [];

    /**
     * @var array<string, list<string>>
     */
    private array $lists = [];

    /**
     * @var array<string, bool>
     */
    private array $flags = [];

    /**
     * @var array<string, list<string>>
     */
    private array $extensions = [];

    /**
     * @var array<string, bool>
     */
    private array $seen = [];

    /**
     * Reads keywords until the closing paren; keywords are matched case-insensitively.
     *
     * @param array<string, KeywordKind> $keywords the keywords this definition type accepts
     * @throws SchemaParseException
     */
    public static function read(
        SchemaDefinitionReader $reader,
        array $keywords,
    ): self {
        $body = new self();

        while (!$reader->isNext(')')) {
            if ($reader->atEnd()) {
                $reader->error('Unterminated definition, expected ")"');
            }

            $at = $reader->offset();
            $body->readKeyword(
                $reader,
                $keywords,
            );

            if ($reader->offset() === $at) {
                $reader->error('Expected a keyword');
            }
        }

        $reader->expect(')');

        return $body;
    }

    public function string(string $keyword): ?string
    {
        return $this->strings[$keyword] ?? null;
    }

    /**
     * @return list<string>
     */
    public function values(string $keyword): array
    {
        return $this->lists[$keyword] ?? [];
    }

    public function flag(string $keyword): bool
    {
        return $this->flags[$keyword] ?? false;
    }

    /**
     * @return array<string, list<string>>
     */
    public function extensions(): array
    {
        return $this->extensions;
    }

    /**
     * @param array<string, KeywordKind> $keywords
     * @throws SchemaParseException
     */
    private function readKeyword(
        SchemaDefinitionReader $reader,
        array $keywords,
    ): void {
        $keyword = strtoupper($reader->readBareToken());

        if (str_starts_with($keyword, self::EXTENSION_PREFIX)) {
            $this->claim(
                $reader,
                $keyword,
            );
            $this->extensions[$keyword] = $reader->readQdstrings();

            return;
        }

        $kind = $keywords[$keyword] ?? null;

        if ($kind === null) {
            $reader->error(sprintf(
                'Unknown keyword "%s"',
                $keyword,
            ));
        }

        $this->claim(
            $reader,
            $keyword,
        );
        $this->store(
            $reader,
            $keyword,
            $kind,
        );
    }

    /**
     * @throws SchemaParseException
     */
    private function store(
        SchemaDefinitionReader $reader,
        string $keyword,
        KeywordKind $kind,
    ): void {
        match ($kind) {
            KeywordKind::Flag => $this->flags[$keyword] = true,
            KeywordKind::QdString => $this->strings[$keyword] = $reader->readQdstring(),
            KeywordKind::QdStrings => $this->lists[$keyword] = $reader->readQdstrings(),
            KeywordKind::Oid => $this->strings[$keyword] = $reader->readOid(),
            KeywordKind::Oids => $this->lists[$keyword] = $reader->readOids(),
        };
    }

    /**
     * Records a keyword as present, rejecting a second occurrence of it.
     *
     * @throws SchemaParseException
     */
    private function claim(
        SchemaDefinitionReader $reader,
        string $keyword,
    ): void {
        if (isset($this->seen[$keyword])) {
            $reader->error(sprintf(
                'Duplicate keyword "%s"',
                $keyword,
            ));
        }

        $this->seen[$keyword] = true;
    }
}
