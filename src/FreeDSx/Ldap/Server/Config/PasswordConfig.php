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

namespace FreeDSx\Ldap\Server\Config;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\DefaultPasswordQualityChecker;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\PasswordQualityCheckerInterface;

/**
 * How passwords are governed and stored, which is server wide even where the policy applied is per entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PasswordConfig
{
    private ?PasswordPolicy $policy = null;

    private ?Dn $defaultPolicyDn = null;

    private PasswordHashScheme $hashScheme = PasswordHashScheme::Bcrypt;

    private ?int $hashCost = null;

    private ?PasswordQualityCheckerInterface $qualityChecker = null;

    /**
     * @param positive-int $maxPasswordValues
     *
     * @throws InvalidArgumentException when the password value limit is below 1
     */
    public function __construct(
        private PasswordHashLimits $hashLimits = new PasswordHashLimits(),
        private bool $allowPreHashedPasswords = false,
        private int $maxPasswordValues = 1,
    ) {
        self::assertMaxPasswordValues($maxPasswordValues);
    }

    /**
     * In-memory fallback policy applied to users that do not resolve a pwdPolicy entry from the DIT.
     */
    public function getPolicy(): ?PasswordPolicy
    {
        return $this->policy;
    }

    public function setPolicy(?PasswordPolicy $policy): self
    {
        $this->policy = $policy;

        return $this;
    }

    /**
     * DN of the default pwdPolicy entry used when a user has no pwdPolicySubentry pointer.
     */
    public function getDefaultPolicyDn(): ?Dn
    {
        return $this->defaultPolicyDn;
    }

    public function setDefaultPolicyDn(?Dn $dn): self
    {
        $this->defaultPolicyDn = $dn;

        return $this;
    }

    /**
     * Output scheme used by the password hasher when writing a new password.
     */
    public function getHashScheme(): PasswordHashScheme
    {
        return $this->hashScheme;
    }

    public function setHashScheme(PasswordHashScheme $scheme): self
    {
        $this->hashScheme = $scheme;

        return $this;
    }

    /**
     * Work factor the hasher applies, or null for the default of the scheme in use.
     */
    public function getHashCost(): ?int
    {
        return $this->hashCost;
    }

    /**
     * Worth raising as hardware gets faster, since a cost chosen at install time weakens as it ages.
     */
    public function setHashCost(?int $cost): self
    {
        $this->hashCost = $cost;

        return $this;
    }

    /**
     * The most work a stored hash may ask for; it never falls below what the configured scheme and cost produce.
     */
    public function getHashLimits(): PasswordHashLimits
    {
        return $this->hashLimits;
    }

    public function setHashLimits(PasswordHashLimits $limits): self
    {
        $this->hashLimits = $limits;

        return $this;
    }

    /**
     * Whether any writer may store a pre-hashed userPassword value, rather than only administrators and the server.
     */
    public function isAllowPreHashedPasswords(): bool
    {
        return $this->allowPreHashedPasswords;
    }

    public function setAllowPreHashedPasswords(bool $allow): self
    {
        $this->allowPreHashedPasswords = $allow;

        return $this;
    }

    /**
     * How many userPassword values an entry may hold; a failed bind verifies every one.
     *
     * @return positive-int
     */
    public function getMaxPasswordValues(): int
    {
        return $this->maxPasswordValues;
    }

    /**
     * @param positive-int $max
     *
     * @throws InvalidArgumentException when the limit is below 1
     */
    public function setMaxPasswordValues(int $max): self
    {
        self::assertMaxPasswordValues($max);
        $this->maxPasswordValues = $max;

        return $this;
    }

    /**
     * Quality check applied to new passwords before they are hashed and stored.
     */
    public function getQualityChecker(): PasswordQualityCheckerInterface
    {
        return $this->qualityChecker ??= new DefaultPasswordQualityChecker();
    }

    public function setQualityChecker(PasswordQualityCheckerInterface $checker): self
    {
        $this->qualityChecker = $checker;

        return $this;
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function assertMaxPasswordValues(int $max): void
    {
        if ($max >= 1) {
            return;
        }

        throw new InvalidArgumentException('The password value limit must be at least 1.');
    }
}
