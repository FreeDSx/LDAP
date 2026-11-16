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

use FreeDSx\Ldap\Operation\ResultCode;

/**
 * Decision returned by {@see PasswordPolicyEngine} methods.
 *
 * @api
 */
final readonly class PasswordPolicyOutcome
{
    /**
     * @param ?int $errorCode A {@see \FreeDSx\Ldap\Control\PwdPolicyError} constant, or null when no error.
     * @param ?int $timeBeforeExpiration Seconds until expiration; mutually exclusive with $graceRemaining.
     * @param ?int $graceRemaining Grace logins left
     */
    public function __construct(
        public bool $denied,
        public int $ldapResultCode = ResultCode::SUCCESS,
        public ?int $errorCode = null,
        public ?int $timeBeforeExpiration = null,
        public ?int $graceRemaining = null,
        public string $diagnostic = '',
    ) {}

    public static function allow(): self
    {
        return new self(denied: false);
    }

    public static function allowWithExpirationWarning(int $seconds): self
    {
        return new self(
            denied: false,
            timeBeforeExpiration: $seconds,
        );
    }

    public static function allowWithGraceWarning(int $remaining): self
    {
        return new self(
            denied: false,
            graceRemaining: $remaining,
        );
    }

    public static function allowWithError(
        int $errorCode,
        string $diagnostic = '',
    ): self {
        return new self(
            denied: false,
            errorCode: $errorCode,
            diagnostic: $diagnostic,
        );
    }

    public static function deny(
        int $errorCode,
        int $ldapResultCode,
        string $diagnostic,
    ): self {
        return new self(
            denied: true,
            ldapResultCode: $ldapResultCode,
            errorCode: $errorCode,
            diagnostic: $diagnostic,
        );
    }

    /**
     * The same decision without its error, for a client that is not told why it was refused.
     */
    public function withoutError(): self
    {
        return new self(
            $this->denied,
            $this->ldapResultCode,
            null,
            $this->timeBeforeExpiration,
            $this->graceRemaining,
            $this->diagnostic,
        );
    }

    public function hasResponseControlPayload(): bool
    {
        return $this->errorCode !== null
            || $this->timeBeforeExpiration !== null
            || $this->graceRemaining !== null;
    }
}
