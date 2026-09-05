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

namespace FreeDSx\Ldap\Server\Backend\Storage\Import;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\AnswerableExceptionInterface;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Write\BulkLoadOptions;
use FreeDSx\Ldap\Server\Backend\Write\Routing\WriteRequestRouter;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Token\SystemToken;

use function sprintf;

/**
 * Bulk-loads entries through the server's add operation, under a single atomic write.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LdapImporter
{
    public function __construct(
        private EntryStorageInterface $storage,
        private WriteRequestRouter $router,
        private EventLogger $eventLogger = new EventLogger(null),
    ) {}

    /**
     * Stream entries through the add operation under a single atomic write.
     *
     * Input must be in depth-first order (each entry's parent appears before its children). Unsorted input will fail
     * at the parent check.
     *
     * @param iterable<Entry> $entries
     * @param Dn $creatorDn recorded as creatorsName/modifiersName on entries that do not carry their own.
     * @param bool $ignoreValidation when true, relaxes the schema rules.
     * @param bool $replaceExisting when true, an entry already at the same DN is overwritten rather than refused.
     * @throws InvalidArgumentException when the creator DN is malformed
     * @throws OperationException when an entry is refused by the add operation, including one whose parent is absent
     */
    public function importEntries(
        iterable $entries,
        Dn $creatorDn = new Dn(''),
        bool $ignoreValidation = false,
        bool $replaceExisting = false,
    ): void {
        $this->assertValidCreatorDn($creatorDn);
        $result = new ImportResult();

        try {
            $this->storage->atomic(fn() => $this->load(
                $entries,
                $creatorDn,
                $ignoreValidation,
                $replaceExisting,
                $result,
            ));
        } catch (AnswerableExceptionInterface $e) {
            $this->recordFailure(
                $result,
                $e,
            );

            throw $e;
        }

        $this->recordOutcome($result);
    }

    /**
     * @param iterable<Entry> $entries
     * @throws OperationException
     */
    private function load(
        iterable $entries,
        Dn $creatorDn,
        bool $ignoreValidation,
        bool $replaceExisting,
        ImportResult $result,
    ): void {
        foreach ($entries as $entry) {
            // Read before the write, since afterwards the entry is present either way.
            $wasPresent = $replaceExisting
                && $this->storage->exists($entry->getDn()->normalize());

            $this->router->route(
                new AddRequest($entry),
                $this->contextFor(
                    $creatorDn,
                    $ignoreValidation,
                    $replaceExisting,
                ),
            );

            $wasPresent
                ? $result->recordReplaced($entry->getDn())
                : $result->recordAdded();
        }
    }

    /**
     * A fresh context per entry, so the schema violations of one are not carried into the next.
     */
    private function contextFor(
        Dn $creatorDn,
        bool $ignoreValidation,
        bool $replaceExisting,
    ): WriteContext {
        // Relaxing through the control keeps the violations recorded rather than discarded.
        $controls = $ignoreValidation
            ? new ControlBag(new Control(Control::OID_RELAX_RULES))
            : new ControlBag();

        return WriteContext::bulkLoad(
            new SystemToken(),
            $controls,
            new BulkLoadOptions(
                $creatorDn,
                $replaceExisting,
            ),
        );
    }

    /**
     * Recorded once the batch commits, so a rollback leaves no trace of writes that did not happen.
     */
    private function recordOutcome(ImportResult $result): void
    {
        foreach ($result->replaced() as $dn) {
            $this->eventLogger->record(
                ServerEvent::EntryReplaced,
                [EventContext::TARGET => [EventContext::DN => $dn->toString()]],
            );
        }

        $this->eventLogger->record(
            ServerEvent::BulkImportCompleted,
            $this->counts($result),
        );
    }

    /**
     * The batch rolled back, so the counts say how far it got rather than what it left behind.
     */
    private function recordFailure(
        ImportResult $result,
        AnswerableExceptionInterface $exception,
    ): void {
        $this->eventLogger->recordFailure(
            ServerEvent::BulkImportFailed,
            $exception instanceof OperationException
                ? $exception
                // The log wants the cause's own message, which is more specific than what a client is told.
                : new OperationException(
                    $exception->getMessage(),
                    $exception->getCode(),
                    $exception,
                ),
            $this->counts($result),
        );
    }

    /**
     * @return array<string, int>
     */
    private function counts(ImportResult $result): array
    {
        return [
            EventContext::ENTRIES_ADDED => $result->added(),
            EventContext::ENTRIES_REPLACED => $result->replacedCount(),
        ];
    }

    /**
     * @throws InvalidArgumentException when the creator DN is malformed
     */
    private function assertValidCreatorDn(Dn $creatorDn): void
    {
        if (Dn::isValid($creatorDn)) {
            return;
        }

        throw new InvalidArgumentException(sprintf(
            'The import creator DN "%s" is not a valid DN.',
            $creatorDn->toString(),
        ));
    }
}
