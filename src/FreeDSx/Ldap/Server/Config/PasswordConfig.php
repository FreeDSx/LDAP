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
}
