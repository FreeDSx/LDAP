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

namespace FreeDSx\Ldap\Server\PasswordPolicy;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;

/**
 * Locates the {@see PasswordPolicy} that governs a given user entry.
 *
 * One instance is constructed per request so the internal cache lives request-scoped.
 */
final class PasswordPolicyResolver
{
    /**
     * @var array<string, ?PasswordPolicy> normalized DN string to decoded policy (null = not found in DIT)
     */
    private array $cache = [];

    public function __construct(
        private readonly LdapBackendInterface $backend,
        private readonly ?Dn $defaultPolicyDn,
        private readonly ?PasswordPolicy $inMemoryFallback,
    ) {}

    public function resolveFor(Entry $user): ?PasswordPolicy
    {
        return $this->fromUserSubentry($user)
            ?? $this->fromDefaultDn()
            ?? $this->inMemoryFallback;
    }

    /**
     * The policy that applies with no entry in hand, for a bind name that resolves to nothing.
     */
    public function resolveDefault(): ?PasswordPolicy
    {
        return $this->fromDefaultDn()
            ?? $this->inMemoryFallback;
    }

    private function fromUserSubentry(Entry $user): ?PasswordPolicy
    {
        $value = $user
            ->get(PasswordPolicyOid::NAME_PWD_POLICY_SUBENTRY)
            ?->firstValue();
        if ($value === null || $value === '') {
            return null;
        }

        return $this->loadFromDit(new Dn($value));
    }

    private function fromDefaultDn(): ?PasswordPolicy
    {
        if ($this->defaultPolicyDn === null) {
            return null;
        }

        return $this->loadFromDit($this->defaultPolicyDn);
    }

    private function loadFromDit(Dn $dn): ?PasswordPolicy
    {
        $key = $dn->normalize()->toString();

        if (array_key_exists($key, $this->cache)) {
            return $this->cache[$key];
        }

        $entry = $this->backend->get($dn);
        $policy = $entry !== null ? PasswordPolicy::fromEntry($entry) : null;

        return $this->cache[$key] = $policy;
    }
}
