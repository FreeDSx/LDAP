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

namespace FreeDSx\Ldap\Server\AccessControl\Read;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\AccessControl\WithheldAttributePolicy;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Withholds confidential attributes the identity holds no grant over.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ConfidentialReadScope implements ReadScopeInterface
{
    use ReadsEntryAttributesTrait;

    public function __construct(
        private readonly ReadScopeInterface $inner,
        private readonly WithheldAttributePolicy $policy,
        private readonly TokenInterface $token,
    ) {}

    public function isCurrent(): bool
    {
        return $this->inner->isCurrent();
    }

    public function isEntryVisible(Entry $entry): bool
    {
        return $this->inner->isEntryVisible($entry);
    }

    public function verdict(string $name): ReadVerdict
    {
        $verdict = $this->inner->verdict($name);

        if ($verdict === ReadVerdict::Deny || !$this->policy->isConfidential($name)) {
            return $verdict;
        }

        return ReadVerdict::PerEntry;
    }

    public function isReadableOn(
        string $name,
        Dn $dn,
    ): bool {
        if (!$this->inner->isReadableOn($name, $dn)) {
            return false;
        }

        return !$this->policy->isWithheldFromResult(
            $name,
            $this->token,
        );
    }
}
