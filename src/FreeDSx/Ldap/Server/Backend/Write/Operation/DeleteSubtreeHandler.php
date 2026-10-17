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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteSubtreeCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Operation\FailureAnswerTrait;
use Throwable;

use function microtime;
use function min;
use function sprintf;

use const PHP_INT_MAX;

/**
 * Removes an entry along with everything beneath it, leaves first and a bounded number of entries per transaction.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DeleteSubtreeHandler
{
    use FailureAnswerTrait;

    /**
     * Entries removed in one transaction, which bounds how long it holds their locks.
     */
    private const CHUNK_SIZE = 1000;

    /**
     * Entries one request removes before it stops short of the base and has to be resubmitted.
     */
    private const MAX_ENTRIES_PER_REQUEST = 25_000;

    /**
     * Transactions in a row that may remove nothing before the request gives up.
     */
    private const MAX_IDLE_ROUNDS = 3;

    /**
     * The pause between transactions that lets other operations in.
     */
    private const PAUSE_SECONDS = 0.001;

    public function __construct(
        private EntryPlacementGuard $placement,
        private SubtreeChunkRemover $chunks,
        private EventLogger $eventLogger = new EventLogger(null),
        private SleeperInterface $sleeper = new BlockingSleeper(),
        private int $maxEntries = self::MAX_ENTRIES_PER_REQUEST,
    ) {}

    /**
     * @throws OperationException
     */
    public function handle(
        DeleteSubtreeCommand $command,
        WriteContext $context,
    ): void {
        $base = $command->dn->normalize();

        // A naming context is refused before anything beneath it is removed.
        $this->placement->assertSubtreeDeletePlacement($command->dn);

        $progress = new SubtreeDeleteProgress();
        $startedAt = microtime(true);

        try {
            $this->deleteInChunks(
                $base,
                $context,
                $progress,
            );
        } catch (Throwable $e) {
            throw $this->withProgress(
                $e,
                $progress,
            );
        } finally {
            $this->recordProgress(
                $command->dn,
                $context,
                $progress,
                $startedAt,
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function deleteInChunks(
        Dn $base,
        WriteContext $context,
        SubtreeDeleteProgress $progress,
    ): void {
        $queue = $this->chunks->queueFor($base);
        $budget = $context->isSystem()
            ? PHP_INT_MAX
            : $this->maxEntries;
        $chunkContext = $context;

        while (!$progress->isComplete()) {
            $chunk = $queue->next(min(
                self::CHUNK_SIZE,
                $budget - $progress->deleted(),
            ));
            if ($chunk === []) {
                break;
            }

            $this->deleteNext(
                $base,
                $chunk,
                $chunkContext,
                $queue,
                $progress,
            );
            $chunkContext = $context->withoutControlEvaluator();

            if (!$progress->isComplete()) {
                // gives other coroutines a chance to work (for coroutine-based runners
                $this->sleeper->sleep(self::PAUSE_SECONDS);
            }
        }

        $this->assertComplete($progress);
        $context->responseControls()->add($progress->toControl());
    }

    /**
     * @param list<string> $chunk canonical DNs, each after its children
     *
     * @throws OperationException
     */
    private function deleteNext(
        Dn $base,
        array $chunk,
        WriteContext $context,
        DeletionQueue $queue,
        SubtreeDeleteProgress $progress,
    ): void {
        $outcome = $this->chunks->removeChunk(
            $base,
            $chunk,
            $context,
        );
        // Only after the commit, so a transaction retried after a deadlock never requeues twice.
        $queue->requeue(
            $outcome->strays,
            $outcome->blocked,
        );
        $progress->record($outcome);
        $this->assertStillRemoving($progress);
    }

    /**
     * @throws OperationException
     */
    private function assertStillRemoving(SubtreeDeleteProgress $progress): void
    {
        if ($progress->idleRounds() < self::MAX_IDLE_ROUNDS) {
            return;
        }

        throw new OperationException(
            'The subtree delete made no progress.',
            ResultCode::BUSY,
        );
    }

    /**
     * @throws OperationException
     */
    private function assertComplete(SubtreeDeleteProgress $progress): void
    {
        if ($progress->isComplete()) {
            return;
        }

        throw new OperationException(
            sprintf(
                '%d entries deleted; resubmit to continue.',
                $progress->deleted(),
            ),
            ResultCode::ADMIN_LIMIT_EXCEEDED,
        );
    }

    /**
     * The failure as the client would be answered, also saying how many entries the request removed before it.
     */
    private function withProgress(
        Throwable $failure,
        SubtreeDeleteProgress $progress,
    ): Throwable {
        $answer = $this->answerFor($failure);
        if ($answer === null || $progress->deleted() === 0) {
            return $failure;
        }

        return new OperationException(
            $answer->getMessage(),
            $answer->getCode(),
            $failure,
            $answer->getMatchedDn(),
            new ControlBag(
                $progress->toControl(),
                ...$answer->controls()->toArray(),
            ),
        );
    }

    private function recordProgress(
        Dn $dn,
        WriteContext $context,
        SubtreeDeleteProgress $progress,
        float $startedAt,
    ): void {
        if ($progress->deleted() === 0) {
            return;
        }

        $this->eventLogger->record(
            ServerEvent::SubtreeDeleted,
            [
                EventContext::TARGET => [EventContext::DN => $dn->toString()],
                EventContext::ENTRIES_DELETED => $progress->deleted(),
                EventContext::COMPLETE => $progress->isComplete(),
                EventContext::DURATION_SECONDS => microtime(true) - $startedAt,
            ],
            $context->getToken(),
        );
    }
}
