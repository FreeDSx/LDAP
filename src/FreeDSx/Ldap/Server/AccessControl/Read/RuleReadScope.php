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
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\AclRuleIndex;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\AccessControl\Subject\TokenDecidedSubjectInterface;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use FreeDSx\Ldap\Server\AccessControl\Target\DnTargetMatcher;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Decides once per request what the rules make of an attribute or entry anywhere, leaving the rest to each entry's DN.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RuleReadScope implements ReadScopeInterface
{
    use ReadsEntryAttributesTrait;

    /**
     * Whether an entry no search rule names by DN is visible, or null when each entry must be checked.
     */
    private ?bool $visibility = null;

    /**
     * @var array<string, true> The canonical DNs search rules name, each always checked against the rules.
     */
    private array $namedDns = [];

    private bool $isVisibilityClassified = false;

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
        if (!$this->isVisibilityClassified) {
            $this->classifyVisibility();
        }

        $isNamed = $this->namedDns !== [] && isset($this->namedDns[$entry->getDn()->normalizedString()]);
        if ($this->visibility === null || $isNamed) {
            return $this->policy->isEntryVisible(
                $this->token,
                $entry,
            );
        }

        return $this->visibility;
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

            if ($this->subjectMatches($rule->subject, $rule->effect)) {
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
     * Every entry no rule names by DN is decided by the first remaining rule that matches anywhere.
     */
    private function classifyVisibility(): void
    {
        $this->isVisibilityClassified = true;

        foreach ($this->index->operationRules(OperationType::Search) as $rule) {
            if ($rule->target instanceof DnTargetMatcher) {
                $this->namedDns[$rule->target->normalizedDn()] = true;

                continue;
            }

            if (!$rule->target instanceof AnyTargetMatcher || !$rule->subject instanceof TokenDecidedSubjectInterface) {
                return;
            }

            if ($this->subjectMatches($rule->subject, $rule->effect)) {
                $this->visibility = $rule->effect === Effect::Allow;

                return;
            }
        }

        $this->visibility = false;
    }

    /**
     * A subject that cannot be decided counts as matching a deny, as it does when each entry is checked.
     */
    private function subjectMatches(
        SubjectMatcherInterface $subject,
        Effect $effect,
    ): bool {
        try {
            return $subject->matches(
                $this->token,
                null,
            );
        } catch (SubjectEvaluationException) {
            return $effect === Effect::Deny;
        }
    }
}
