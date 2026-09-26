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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Rules;

/**
 * Rules governing account lockout from failed binds (draft-behera-10 §5.2.9-5.2.10, §5.2.17-5.2.18).
 *
 * @api
 */
final readonly class PasswordLockoutRules
{
    /**
     * @param int<0, max>|null $duration
     * @param int<0, max>|null $maxFailure
     * @param int<0, max>|null $failureCountInterval
     * @param int<0, max>|null $maxRecordedFailure Failure timestamps kept, which lockout alone does not bound.
     * @param int<0, max>|null $minDelay
     * @param int<0, max>|null $maxDelay
     */
    public function __construct(
        public ?bool $enabled = null,
        public ?int $duration = null,
        public ?int $maxFailure = null,
        public ?int $failureCountInterval = null,
        public ?int $maxRecordedFailure = null,
        public ?int $minDelay = null,
        public ?int $maxDelay = null,
    ) {}
}
