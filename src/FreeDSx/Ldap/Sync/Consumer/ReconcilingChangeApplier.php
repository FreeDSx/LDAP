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

namespace FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;

/**
 * Wraps an applier to drop a subject's replica-local password-policy state once the primary's authoritative entry
 * supersedes it, so the entry becomes the single source of truth.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ReconcilingChangeApplier implements ChangeApplierInterface
{
    public function __construct(
        private ChangeApplierInterface $baseApplier,
        private ReplicaPasswordStateStoreInterface $passwordStateStore,
    ) {}

    public function beginRefresh(): void
    {
        $this->baseApplier->beginRefresh();
    }

    /**
     * The entry is written before any local state is dropped, and that order must hold: a bind reading no local state
     * concludes the entry it superseded is already durable, and re-reads the entry rather than allowing.
     */
    public function apply(
        SyncEntryResult $result,
        Session $session,
    ): void {
        $this->baseApplier->apply($result, $session);

        // A present marker changes nothing.
        if ($result->isPresent()) {
            return;
        }

        $dn = $result->getEntry()
            ->getDn()
            ->normalize();

        // Drops it outright on delete, whether the underlying storage already does.
        if ($result->isDelete()) {
            $this->passwordStateStore->discard($dn);

            return;
        }

        $this->passwordStateStore->discardIfSuperseded(
            $dn,
            UserPasswordState::fromEntry($result->getEntry()),
        );
    }

    public function reconcile(): void
    {
        $this->baseApplier->reconcile();
    }
}
