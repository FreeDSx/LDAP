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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Decision;

/**
 * Result of an engine "record" method: the bookkeeping deltas plus the outcome to surface.
 */
final readonly class RecordedOutcome
{
    /**
     * @param bool $stored Whether the changes were kept and the state the outcome reports holds.
     */
    public function __construct(
        public PasswordPolicyOutcome $outcome,
        public OperationalChanges $changes,
        public float $delaySeconds = 0.0,
        public bool $stored = true,
    ) {}

    /**
     * The same decision for a bind whose state could not be kept, carrying none of the changes it would have made.
     */
    public function unstored(): self
    {
        return new self(
            $this->outcome,
            OperationalChanges::none(),
            $this->delaySeconds,
            false,
        );
    }
}
