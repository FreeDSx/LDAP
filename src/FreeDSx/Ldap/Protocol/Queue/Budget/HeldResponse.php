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

namespace FreeDSx\Ldap\Protocol\Queue\Budget;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;

use function ceil;
use function count;
use function strlen;

/**
 * The entries one response collects before it is written, held against the process budget and an identity's share.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class HeldResponse
{
    /**
     * What an entry holds for each byte of its DN and values, covering whole pages for large values.
     */
    private const HELD_BYTES_PER_BYTE = 1.2;

    /**
     * What an entry holds for each of its values on top of their bytes.
     */
    private const HELD_BYTES_PER_VALUE = 90;

    /**
     * What an entry holds for each of its attributes, including a typical name.
     */
    private const HELD_BYTES_PER_ATTRIBUTE = 520;

    /**
     * What an entry and its DN hold on their own.
     */
    private const HELD_BYTES_PER_ENTRY = 400;

    private int $bytes = 0;

    /**
     * @param int $limit the bytes the process may hold, or 0 for no limit.
     */
    public function __construct(
        private readonly RequestBudget $budget,
        private readonly int $limit,
        private readonly BudgetShare $share,
    ) {}

    public function __destruct()
    {
        if ($this->bytes === 0) {
            return;
        }

        $this->budget->release(
            $this->bytes,
            $this->share->key,
        );
    }

    /**
     * The bytes an entry holds, from its DN, its attributes and their values.
     */
    public static function estimate(Entry $entry): int
    {
        $bytes = strlen($entry->getDn()->toString());
        $values = 0;
        $attributes = $entry->getAttributes();

        foreach ($attributes as $attribute) {
            foreach ($attribute->getValues() as $value) {
                $bytes += strlen($value);
                $values++;
            }
        }

        return (int) ceil($bytes * self::HELD_BYTES_PER_BYTE)
            + $values * self::HELD_BYTES_PER_VALUE
            + count($attributes) * self::HELD_BYTES_PER_ATTRIBUTE
            + self::HELD_BYTES_PER_ENTRY;
    }

    /**
     * Counts the entry until the response is freed, or returns false when the process or the share has no room.
     */
    public function hold(Entry $entry): bool
    {
        if ($this->limit === 0) {
            return true;
        }
        $estimate = self::estimate($entry);

        if (!$this->budget->take($estimate, $this->limit, $this->share)) {
            return false;
        }
        $this->bytes += $estimate;

        return true;
    }

    /**
     * Refuses a response with no room for its first entry, as past the admin limit when that entry could never fit.
     *
     * @throws OperationException
     */
    public function refuse(Entry $entry): never
    {
        $estimate = self::estimate($entry);

        if ($estimate > $this->share->limit) {
            throw new OperationException(
                'The entry is larger than the server can hold.',
                ResultCode::ADMIN_LIMIT_EXCEEDED,
            );
        }
        if ($this->budget->heldBy($this->share) + $estimate > $this->share->limit) {
            throw new OperationException(
                'The server holds as much as it allows one identity to.',
                ResultCode::BUSY,
            );
        }

        throw new OperationException(
            'The server is too busy to hold the response.',
            ResultCode::BUSY,
        );
    }
}
