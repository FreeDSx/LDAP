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

namespace FreeDSx\Ldap\Server\SearchLimit;

use FreeDSx\Ldap\Server\AccessControl\BackendAwareInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Resolves per-identity search limits via ordered rules, first match wins, falling back to the global default.
 */
final class SearchLimitResolver implements SearchLimitResolverInterface, BackendAwareInterface
{
    public function __construct(
        private readonly SearchLimitRules $rules,
        private readonly SearchLimits $default,
    ) {}

    public function setBackend(ReadBackendInterface $backend): void
    {
        foreach ($this->rules->rules as $rule) {
            if ($rule->subject instanceof BackendAwareInterface) {
                $rule->subject->setBackend($backend);
            }
        }
    }

    public function resolve(TokenInterface $token): SearchLimits
    {
        foreach ($this->rules->rules as $rule) {
            // Limit rules carry no target entry, so a subject needing one cannot match.
            if (!$rule->subject->matches($token, null)) {
                continue;
            }

            // A rule overrides only the caps it names.
            return $rule->limits->mergedOver($this->default);
        }

        return $this->default;
    }
}
