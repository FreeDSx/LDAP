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

/**
 * A bounded memo read straight from its answers array.
 *
 * @template T
 *
 * @internal
 */
class ArrayAccessMemo
{
    /**
     * @use BoundedMemoTrait<T>
     */
    use BoundedMemoTrait;

    /**
     * Read directly for speed and written only through remember().
     *
     * @var array<array-key, T>
     */
    public array $answers = [];

    public function __construct(private readonly int $capacity) {}
}
