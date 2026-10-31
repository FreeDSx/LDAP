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

use FreeDSx\Ldap\Entry\Attribute;

use function count;
use function is_string;
use function strlen;

/**
 * Holds at most a fixed number of answers, emptying or keeping its first ones once full as its scope decides.
 *
 * @template T
 *
 * @internal
 */
trait BoundedMemoTrait
{
    /**
     * Remembers the answer under the key unless the key is too long to keep, and returns it.
     *
     * @param T $answer
     * @return T
     */
    public function remember(
        int|string $key,
        mixed $answer,
    ): mixed {
        // A longer key could keep a client's string alive for as long as the memo lives.
        if (is_string($key) && strlen($key) > Attribute::MAX_TYPE_LENGTH) {
            return $answer;
        }
        $full = count($this->answers) >= $this->capacity;
        if ($full && $this->scope === MemoScope::Request) {
            return $answer;
        }
        if ($full) {
            $this->answers = [];
        }
        $this->answers[$key] = $answer;

        return $answer;
    }
}
