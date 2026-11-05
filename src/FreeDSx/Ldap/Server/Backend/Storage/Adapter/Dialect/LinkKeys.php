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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;

use function array_key_last;
use function array_pad;
use function count;
use function max;
use function min;
use function sprintf;

/**
 * The entries a link read covers, by the span of their ids when those sit close together and by the ids otherwise.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class LinkKeys
{
    /**
     * How many ids wide a span may be per id it covers before reading the ids themselves costs less.
     */
    private const MAX_SPAN_PER_ID = 2;

    /**
     * The lengths a list of ids is padded to, so a few statements serve every chunk.
     */
    private const LIST_LENGTHS = [
        16,
        100,
    ];

    /**
     * @param list<int> $params
     */
    private function __construct(
        private bool $isSpan,
        private array $params,
    ) {}

    public static function span(
        int $first,
        int $last,
    ): self {
        return new self(
            true,
            [
                $first,
                $last,
            ],
        );
    }

    /**
     * @param non-empty-list<int> $ids
     */
    public static function covering(array $ids): self
    {
        $first = min($ids);
        $last = max($ids);

        if ($last - $first + 1 <= count($ids) * self::MAX_SPAN_PER_ID) {
            return self::span(
                $first,
                $last,
            );
        }

        return new self(
            false,
            self::padded($ids),
        );
    }

    /**
     * Whether these entries are read by the span of their ids.
     */
    public function isSpan(): bool
    {
        return $this->isSpan;
    }

    /**
     * The condition selecting these entries by the given id column.
     */
    public function condition(string $column): string
    {
        return $this->isSpan
            ? sprintf(
                '%s BETWEEN ? AND ?',
                $column,
            )
            : sprintf(
                '%s IN (%s)',
                $column,
                SqlFilterUtility::markers(count($this->params)),
            );
    }

    /**
     * @return list<int>
     */
    public function params(): array
    {
        return $this->params;
    }

    /**
     * Repeats the last id up to the next list length, which leaves the entries the list selects unchanged.
     *
     * @param non-empty-list<int> $ids
     *
     * @return list<int>
     */
    private static function padded(array $ids): array
    {
        foreach (self::LIST_LENGTHS as $length) {
            if (count($ids) <= $length) {
                return array_pad(
                    $ids,
                    $length,
                    $ids[array_key_last($ids)],
                );
            }
        }

        return $ids;
    }
}
