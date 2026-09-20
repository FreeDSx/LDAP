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

namespace Tests\Performance\FreeDSx\Ldap\Workload;

use InvalidArgumentException;

/**
 * Weighted op picker. Parses a "bind=5,search=90,add=2" spec and returns ops in proportion.
 */
final class WorkloadMix
{
    public const SUPPORTED_OPS = [
        'bind',
        'search-read',
        'search-eq',
        'search-sub',
        'search-substr',
        'search-suffix',
        'search-range',
        'search-list',
        'search-and',
        'search-or',
        'search-sort',
        'search-paged',
        'compare',
        'add',
        'modify',
        'delete',
        'group-add-member',
        'group-del-member',
        'group-reset',
    ];

    /**
     * Ops that need a seeded group to work against.
     *
     * @var list<string>
     */
    public const GROUP_OPS = [
        'group-add-member',
        'group-del-member',
        'group-reset',
    ];

    /**
     * @var array<string, int> op name -> declared weight
     */
    private readonly array $weights;

    /**
     * @var list<string> ops indexed in order matching $cumulative
     */
    private readonly array $ops;

    /**
     * @var list<int> cumulative weights (strictly increasing)
     */
    private readonly array $cumulative;

    private readonly int $total;

    public function __construct(string $spec)
    {
        $weights = [];

        foreach (explode(',', $spec) as $part) {
            $part = trim($part);

            if ($part === '') {
                continue;
            }

            $weights[] = $this->parsePair($part);
        }

        if ($weights === []) {
            throw new InvalidArgumentException('Workload mix spec is empty.');
        }

        $combined = [];
        foreach ($weights as [$op, $w]) {
            $combined[$op] = ($combined[$op] ?? 0) + $w;
        }

        $ops = [];
        $cumulative = [];
        $running = 0;

        foreach ($combined as $op => $w) {
            $running += $w;
            $ops[] = $op;
            $cumulative[] = $running;
        }

        if ($running <= 0) {
            throw new InvalidArgumentException('Workload mix weights must sum to a positive value.');
        }

        $this->weights = $combined;
        $this->ops = $ops;
        $this->cumulative = $cumulative;
        $this->total = $running;
    }

    public function pick(): string
    {
        $roll = mt_rand(1, $this->total);

        foreach ($this->cumulative as $idx => $bound) {
            if ($roll <= $bound) {
                return $this->ops[$idx];
            }
        }

        return $this->ops[count($this->ops) - 1];
    }

    /**
     * @return array<string, int>
     */
    public function weights(): array
    {
        return $this->weights;
    }

    /**
     * Whether the mix draws any of the given ops.
     *
     * @param list<string> $ops
     */
    public function drawsAny(array $ops): bool
    {
        foreach ($ops as $op) {
            if (isset($this->weights[$op])) {
                return true;
            }
        }

        return false;
    }

    public function describe(): string
    {
        $parts = [];
        foreach ($this->weights as $op => $w) {
            $parts[] = "{$op}={$w}";
        }

        return implode(', ', $parts);
    }

    /**
     * @return array{string, int}
     */
    private function parsePair(string $pair): array
    {
        $eq = strpos($pair, '=');
        if ($eq === false) {
            throw new InvalidArgumentException("Invalid mix entry \"{$pair}\": expected op=weight.");
        }

        $op = strtolower(trim(substr($pair, 0, $eq)));
        $weight = (int) trim(substr($pair, $eq + 1));

        if (!in_array($op, self::SUPPORTED_OPS, true)) {
            throw new InvalidArgumentException(sprintf(
                'Unsupported op "%s" in mix. Supported: %s.',
                $op,
                implode(', ', self::SUPPORTED_OPS),
            ));
        }
        if ($weight <= 0) {
            throw new InvalidArgumentException("Mix weight for \"{$op}\" must be positive, got {$weight}.");
        }

        return [$op, $weight];
    }
}
