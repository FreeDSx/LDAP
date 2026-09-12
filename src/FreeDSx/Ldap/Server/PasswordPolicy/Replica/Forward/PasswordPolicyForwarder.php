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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward;

use FreeDSx\Ldap\Exception\ForwardStateException;
use FreeDSx\Ldap\Exception\ForwardStateRejectedException;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Logging\ExceptionLogging;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaForwardState;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use Psr\Log\LoggerInterface;

/**
 * Drains the replica-local password-policy forward queue once, delivering each pending subject by its entryUUID.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PasswordPolicyForwarder
{
    private int $drain = 0;

    /**
     * @var array<string, RefusedForward>
     */
    private array $refused = [];

    public function __construct(
        private readonly ReplicaPasswordStateStoreInterface $store,
        private readonly ForwardStateSenderInterface $sender,
        private readonly ReadBackendInterface $backend,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    /**
     * Forward every pending subject in watermark order, advancing the watermark after each delivery.
     *
     * @return int the number of subjects forwarded
     * @throws ForwardStateException
     */
    public function forwardOnce(): int
    {
        $forwarded = 0;
        $refused = [];
        ++$this->drain;

        foreach ($this->store->listUnforwarded() as $pending) {
            $key = self::keyFor($pending);
            $previous = $this->refusalFor($pending);

            if ($previous !== null && !$previous->isDue($this->drain)) {
                $refused[$key] = $previous;

                continue;
            }

            $uuid = $this->uuidFor($pending);
            if ($uuid === null) {
                $this->reportUnaddressable($pending, $previous);
                $refused[$key] = $this->nextRefusal($pending, $previous);

                continue;
            }

            try {
                $this->sender->send($this->requestFor($pending, $uuid));
            } catch (ForwardStateRejectedException $e) {
                // One subject the primary refuses must not hold back every other subject behind it.
                $this->reportRefusal($pending, $previous, $e);
                $refused[$key] = $this->nextRefusal($pending, $previous);

                continue;
            }

            $this->store->markForwarded(
                $pending->dn,
                $pending->sequence,
            );
            ++$forwarded;
        }

        $this->refused = $refused;

        return $forwarded;
    }

    /**
     * The standing refusal for this subject, or null when its state has moved on and deserves a fresh attempt.
     */
    private function refusalFor(ReplicaForwardState $pending): ?RefusedForward
    {
        $refusal = $this->refused[self::keyFor($pending)] ?? null;

        return $refusal?->sequence === $pending->sequence
            ? $refusal
            : null;
    }

    /**
     * The refusal to carry forward for a subject left pending, widening the retry gap or opening a fresh one.
     */
    private function nextRefusal(
        ReplicaForwardState $pending,
        ?RefusedForward $previous,
    ): RefusedForward {
        return $previous?->again($this->drain)
            ?? RefusedForward::after($pending->sequence, $this->drain);
    }

    /**
     * Normalized, so one subject cannot occupy two entries under two spellings of its DN.
     */
    private static function keyFor(ReplicaForwardState $pending): string
    {
        return $pending->dn
            ->normalize()
            ->toString();
    }

    /**
     * Reported once per subject state to avoid logging this indefinitely.
     */
    private function reportRefusal(
        ReplicaForwardState $pending,
        ?RefusedForward $previous,
        ForwardStateRejectedException $exception,
    ): void {
        if ($previous !== null) {
            return;
        }

        $this->logger?->warning(
            'The primary refused a password-policy forward; leaving it pending and continuing.',
            ExceptionLogging::makeLogContext($exception) + ['dn' => $pending->dn->toString()],
        );
    }

    private function reportUnaddressable(
        ReplicaForwardState $pending,
        ?RefusedForward $previous,
    ): void {
        if ($previous !== null) {
            return;
        }

        $this->logger?->warning(
            'A pending password-policy forward has no resolvable entry UUID; leaving it pending and continuing.',
            ['dn' => $pending->dn->toString()],
        );
    }

    private function uuidFor(ReplicaForwardState $pending): ?string
    {
        return $this->backend
            ->get($pending->dn)
            ?->get(AttributeTypeOid::NAME_ENTRY_UUID)
            ?->firstValue();
    }

    private function requestFor(
        ReplicaForwardState $pending,
        string $uuid,
    ): ForwardPasswordPolicyStateRequest {
        $state = $pending->state->toUserPasswordState($pending->dn);

        return new ForwardPasswordPolicyStateRequest(
            $uuid,
            failureTimes: $state->failureTimes,
            lastSuccess: $state->lastSuccess,
        );
    }
}
