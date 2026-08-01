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

namespace FreeDSx\Ldap\Exception;

use Exception;

use function sprintf;

/**
 * Represents an issue encountered while parsing an RFC 4512 schema definition.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SchemaParseException extends Exception
{
    public function __construct(
        string $message,
        private readonly string $definition = '',
        private readonly int $offset = -1,
    ) {
        parent::__construct(
            $offset >= 0
                ? sprintf('%s (at offset %d in "%s").', $message, $offset, $definition)
                : $message,
        );
    }

    /**
     * The definition string that failed to parse.
     */
    public function getDefinition(): string
    {
        return $this->definition;
    }

    /**
     * The 0-based character offset where parsing failed; -1 when not applicable.
     */
    public function getOffset(): int
    {
        return $this->offset;
    }
}
