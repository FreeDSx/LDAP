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

namespace FreeDSx\Ldap\Server\Utility\Memo;

use Closure;

/**
 * A bounded memo that computes the answers it does not hold.
 *
 * The default for any lookup not made per attribute of every returned entry.
 *
 * @template K of int|string
 * @template T
 *
 * @internal
 */
class BoundedMemo
{
    /**
     * @use BoundedMemoTrait<T>
     */
    use BoundedMemoTrait {
        remember as private;
    }

    /**
     * @var array<array-key, T>
     */
    private array $answers = [];

    /**
     * @param Closure(K): T $compute Answers a key the memo does not hold.
     */
    public function __construct(
        private readonly int $capacity,
        private readonly Closure $compute,
    ) {}

    /**
     * The answer for the key, computed and remembered when it is not already held.
     *
     * @param K $key
     * @return T
     */
    public function for(int|string $key): mixed
    {
        return $this->answers[$key] ?? $this->remember(
            $key,
            ($this->compute)($key),
        );
    }
}
