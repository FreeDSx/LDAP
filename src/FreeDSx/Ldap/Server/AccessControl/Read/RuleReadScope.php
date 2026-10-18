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
use FreeDSx\Ldap\Exception\SubjectEvaluationException;
use FreeDSx\Ldap\Server\AccessControl\AclRuleIndex;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\TokenDecidedSubjectInterface;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Decides once per request what the rules make of an attribute anywhere, leaving the rest to each entry's DN.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RuleReadScope implements ReadScopeInterface
{
    use ReadsEntryAttributesTrait;

    public function __construct(
        private readonly RuleBasedAccessControl $policy,
        private readonly AclRuleIndex $index,
        private readonly TokenInterface $token,
    ) {}

    public function isCurrent(): bool
    {
        return true;
    }

    public function isEntryVisible(Entry $entry): bool
    {
        return $this->policy->isEntryVisible(
            $this->token,
            $entry,
        );
    }

    /**
     * The first rule that matches anywhere decides, as it would on every entry; any rule that needs the entry defers.
     */
    public function verdict(string $name): ReadVerdict
    {
        foreach ($this->index->attributeRules(AttributeAccess::Read, $name) as $rule) {
            if (!$rule->target instanceof AnyTargetMatcher || !$rule->subject instanceof TokenDecidedSubjectInterface) {
                return ReadVerdict::PerEntry;
            }

            if ($this->subjectMatches($rule)) {
                return ReadVerdict::fromEffect($rule->effect);
            }
        }

        return ReadVerdict::Allow;
    }

    public function isReadableOn(
        string $name,
        Dn $dn,
    ): bool {
        return $this->policy->isAttributeReadable(
            $this->token,
            $dn,
            $name,
        );
    }

    /**
     * A subject that cannot be decided counts as matching a deny, as it does when each entry is checked.
     */
    private function subjectMatches(AttributeRule $rule): bool
    {
        try {
            return $rule->subject->matches(
                $this->token,
                null,
            );
        } catch (SubjectEvaluationException) {
            return $rule->effect === Effect::Deny;
        }
    }
}
