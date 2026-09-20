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
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SubjectEvaluationException;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\BackendAwareInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Clock\SystemClock;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use LogicException;

/**
 * Matches when the bound DN is a member of the given LDAP group entry.
 *
 * The read and the membership it decides are both held for a short lifetime. A dropped member keeps matching until
 * that passes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class GroupSubjectMatcher implements SubjectMatcherInterface, BackendAwareInterface
{
    private readonly Dn $groupDn;

    private ?ReadBackendInterface $backend = null;

    private ?Entry $cached = null;

    private ?DateTimeImmutable $cachedAt = null;

    /**
     * @var array<string, bool> Membership already decided this lifetime, keyed by the subject's normalized DN.
     */
    private array $decided = [];

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

    public function setBackend(ReadBackendInterface $backend): void
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
        $memberDn = $token->getResolvedDn();
        $key = $memberDn->normalizedString();

        // Deciding membership asks storage, which is too much to repeat for every entry a search returns.
        return $this->decided[$key] ??= $this->holdsMember(
            $entry,
            $memberDn,
        );
    }

    /**
     * The membership question answered the way a filter would answer it, which is what reaches past a bounded read.
     *
     * @throws SubjectEvaluationException when the member attribute has no equality rule to decide it by
     */
    private function holdsMember(
        Entry $entry,
        Dn $memberDn,
    ): bool {
        try {
            return $this->backend()->compare(
                $entry,
                Filters::equal(
                    $this->memberAttribute,
                    $memberDn->toString(),
                ),
            );
        } catch (OperationException $e) {
            throw new SubjectEvaluationException(
                sprintf(
                    'Membership of the group "%s" could not be decided.',
                    $this->groupDn->toString(),
                ),
                previous: $e,
            );
        }
    }

    private function groupEntry(): ?Entry
    {
        if ($this->cacheTtl <= 0) {
            $this->decided = [];

            return $this->readGroup();
        }

        $now = $this->clock->now();

        if ($this->isCacheExpired($now)) {
            // Decided the same lifetime as the read it was decided from, so a membership change lands with it.
            $this->decided = [];
            $this->cached = $this->readGroup();
            $this->cachedAt = $now;
        }

        return $this->cached;
    }

    /**
     * Only the member attribute, since membership is decided against the group rather than read out of it.
     */
    private function readGroup(): ?Entry
    {
        return $this->backend()->get(
            $this->groupDn,
            new EntryProjection([Attribute::normalizeName($this->memberAttribute)]),
        );
    }

    private function isCacheExpired(DateTimeImmutable $now): bool
    {
        return $this->cachedAt === null
            || ($now->getTimestamp() - $this->cachedAt->getTimestamp()) >= $this->cacheTtl;
    }

    private function backend(): ReadBackendInterface
    {
        if ($this->backend === null) {
            throw new LogicException('No backend set on GroupSubjectMatcher; call setBackend() before use.');
        }

        return $this->backend;
    }
}
