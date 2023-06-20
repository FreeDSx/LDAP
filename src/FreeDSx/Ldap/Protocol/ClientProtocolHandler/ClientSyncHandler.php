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

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use Closure;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshPresent;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Search\Result\ReferralResult;
use FreeDSx\Ldap\Sync\Session;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Result\SyncReferralResult;

class ClientSyncHandler extends ClientBasicHandler
{
    use ClientSearchTrait;

    private ?SyncRequest $syncRequest = null;

    private SyncRequestControl $syncRequestControl;

    private Session $session;

    private ?Closure $syncEntryHandler = null;

    private ?Closure $syncReferralHandler = null;

    private ?Closure $syncIdSetHandler = null;

    /**
     * {@inheritDoc}
     */
    public function handleRequest(ClientProtocolContext $context): ?LdapMessageResponse
    {
        /** @var SearchRequest $request */
        $request = $context->getRequest();
        if ($request->getBaseDn() === null) {
            $request->setBaseDn($context->getOptions()->getBaseDn() ?? null);
        }

        return parent::handleRequest($context);
    }

    /**
     * {@inheritDoc}
     */
    public function handleResponse(
        LdapMessageRequest $messageTo,
        LdapMessageResponse $messageFrom,
        ClientQueue $queue,
        ClientOptions $options,
    ): ?LdapMessageResponse {
        $this->initializeSync($messageTo);

        try {
            do {
                $searchDone = self::search(
                    $messageFrom,
                    $messageTo,
                    $queue,
                );
                if ($this->isRefreshRequired($searchDone)) {
                    $this->syncRequestControl->setCookie(null);
                }
            } while (!$this->isSyncComplete($searchDone));

            return $searchDone;
        } finally {
            $this->resetRequestHandlers();
        }
    }


    /**
     * We need to set up / verify the initial sync session and message handlers before starting the overall sync process.
     */
    private function initializeSync(LdapMessageRequest $messageTo): void
    {
        $this->syncRequestControl = $messageTo->controls()
            ->getByClass(SyncRequestControl::class) ?? throw new RuntimeException(sprintf(
            'Expected a "%s", but there is none.',
            SyncRequestControl::class,
        ));

        if ($this->isContentUpdatePoll()) {
            $syncStage = Session::STAGE_PERSIST;
        } else {
            $syncStage = Session::STAGE_REFRESH;
        }

        $this->session = new Session(
            stage: $syncStage,
            cookie: $this->syncRequestControl->getCookie(),
        );

        /** @var SyncRequest $searchRequest */
        $searchRequest = $messageTo->getRequest();
        $this->syncRequest = $searchRequest;

        // We override these with our own, so save them here for now.
        $this->syncEntryHandler = $searchRequest->getEntryHandler();
        $this->syncReferralHandler = $searchRequest->getReferralHandler();
        $this->syncIdSetHandler = $searchRequest->getIdSetHandler();

        $searchRequest->useEntryHandler($this->processSyncEntry(...));
        $searchRequest->useReferralHandler($this->processSyncReferral(...));
        $searchRequest->useIntermediateResponseHandler($this->processIntermediateResponse(...));
    }

    /**
     * We wrap the handlers with our own at the start of the sync process. This cleans it up so the request has the
     * original handlers at the end of the process again.
     */
    private function resetRequestHandlers(): void
    {
        if ($this->syncRequest === null) {
            return;
        }

        if ($this->syncEntryHandler !== null) {
            $this->syncRequest->useEntryHandler($this->syncEntryHandler);
        }
        if ($this->syncReferralHandler !== null) {
            $this->syncRequest->useReferralHandler($this->syncReferralHandler);
        }
        if ($this->syncIdSetHandler !== null) {
            $this->syncRequest->useIdSetHandler($this->syncIdSetHandler);
        }
    }

    private function isContentUpdatePoll(): bool
    {
        return !empty($this->syncRequestControl->getCookie());
    }

    private function processSyncEntry(EntryResult $entryResult): void
    {
        if ($this->syncEntryHandler === null) {
            return;
        }

        call_user_func(
            $this->syncEntryHandler,
            new SyncEntryResult($entryResult),
            $this->session,
        );
    }

    private function processSyncReferral(ReferralResult $referralResult): void
    {
        if ($this->syncReferralHandler === null) {
            return;
        }

        call_user_func(
            $this->syncReferralHandler,
            new SyncReferralResult($referralResult),
            $this->session,
        );
    }

    private function processIntermediateResponse(LdapMessageResponse $messageFrom): void
    {
        $response = $messageFrom->getResponse();

        if ($response instanceof SyncRefreshDelete) {
            $this->syncRequestControl->setCookie($response->getCookie());
            $this->session
                ->updatePhase(Session::PHASE_DELETE)
                ->updateCookie($response->getCookie());
        } elseif ($response instanceof SyncRefreshPresent) {
            $this->syncRequestControl->setCookie($response->getCookie());
            $this->session
                ->updatePhase(Session::PHASE_PRESENT)
                ->updateCookie($response->getCookie());
        } elseif ($response instanceof SyncNewCookie) {
            $this->session->updateCookie($response->getCookie());
            $this->syncRequestControl->setCookie($response->getCookie());
        } elseif ($response instanceof SyncIdSet && $this->syncIdSetHandler) {
            call_user_func(
                $this->syncIdSetHandler,
                new SyncIdSetResult($messageFrom),
            );
        }
    }

    private function isSyncComplete(LdapMessageResponse $response): bool
    {
        /** @var SearchResultDone $result */
        $result = $response->getResponse();
        $syncDone = $response->controls()
            ->getByClass(SyncDoneControl::class);

        return $syncDone === null
            || $result->getResultCode() === ResultCode::SUCCESS;
    }

    private function isRefreshRequired(LdapMessageResponse $response): bool
    {
        /** @var SearchResultDone $result */
        $result = $response->getResponse();

        return $result->getResultCode() === ResultCode::SYNCHRONIZATION_REFRESH_REQUIRED;
    }
}