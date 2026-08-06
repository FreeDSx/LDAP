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

namespace FreeDSx\Ldap\Server\AccessControl\Subject;

use DateTimeImmutable;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\SubjectEvaluationException;
use FreeDSx\Ldap\Server\AccessControl\BackendAwareInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Clock\SystemClock;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use LogicException;

/**
 * Matches when the bound DN is a member of the given LDAP group entry.
 *
 * The group entry is read through a short-lived cache, since membership is re-checked for every entry a search
 * returns. Dropping a member therefore takes effect within the cache lifetime rather than at once; nothing can be
 * invalidated across processes, so time is the only bound that holds on every runner.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class GroupSubjectMatcher implements SubjectMatcherInterface, BackendAwareInterface
{
    private readonly Dn $groupDn;

    private ?LdapBackendInterface $backend = null;

    private ?Entry $cached = null;

    private ?DateTimeImmutable $cachedAt = null;

    /**
     * @param int $cacheTtl Seconds a membership read is reused for; zero reads the group entry every time.
     */
    public function __construct(
        string $groupDn,
        private readonly string $memberAttribute = 'member',
        private readonly int $cacheTtl = 5,
        private readonly ClockInterface $clock = new SystemClock(),
    ) {
        $this->groupDn = new Dn($groupDn);
    }

    public function setBackend(LdapBackendInterface $backend): void
    {
        $this->backend = $backend;
    }

    public function matches(
        TokenInterface $token,
        ?Dn $targetDn,
    ): bool {
        if ($this->backend === null) {
            throw new SubjectEvaluationException(
                'The group subject has no backend to read membership from.',
            );
        }

        if (!$token instanceof AuthenticatedTokenInterface) {
            return false;
        }

        $entry = $this->groupEntry();
        if ($entry === null) {
            throw new SubjectEvaluationException(sprintf(
                'The group "%s" could not be read to determine membership.',
                $this->groupDn->toString(),
            ));
        }

        // The group exists and simply has no members, which is an answer rather than a failure.
        $memberAttr = $entry->get($this->memberAttribute);
        if ($memberAttr === null) {
            return false;
        }

        $resolvedDn = $token->getResolvedDn()->normalize()->toString();

        foreach ($memberAttr->getValues() as $value) {
            if ((new Dn($value))->normalize()->toString() === $resolvedDn) {
                return true;
            }
        }

        return false;
    }

    private function groupEntry(): ?Entry
    {
        if ($this->cacheTtl <= 0) {
            return $this->backend()->get($this->groupDn);
        }

        $now = $this->clock->now();

        if ($this->isCacheExpired($now)) {
            $this->cached = $this->backend()->get($this->groupDn);
            $this->cachedAt = $now;
        }

        return $this->cached;
    }

    private function isCacheExpired(DateTimeImmutable $now): bool
    {
        return $this->cachedAt === null
            || ($now->getTimestamp() - $this->cachedAt->getTimestamp()) >= $this->cacheTtl;
    }

    private function backend(): LdapBackendInterface
    {
        if ($this->backend === null) {
            throw new LogicException('No backend set on GroupSubjectMatcher; call setBackend() before use.');
        }

        return $this->backend;
    }
}
