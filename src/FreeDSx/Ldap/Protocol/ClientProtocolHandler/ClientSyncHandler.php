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
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Result\SyncReferralResult;
use FreeDSx\Ldap\Sync\Session;

class ClientSyncHandler extends ClientBasicHandler
{
    use ClientSearchTrait;

    private SyncRequest $syncRequest;

    private SyncRequestControl $syncRequestControl;

    private Session $session;

    private ?Closure $syncEntryHandler = null;

    private ?Closure $syncReferralHandler = null;

    private ?Closure $syncIdSetHandler = null;

    private ?Closure $cookieHandler = null;

    public function __construct(
        private readonly ClientQueue $queue,
        private readonly ClientOptions $options,
    ) {
        parent::__construct($this->queue);
    }

    /**
     * {@inheritDoc}
     */
    public function handleRequest(LdapMessageRequest $message): ?LdapMessageResponse
    {
        /** @var SearchRequest $request */
        $request = $message->getRequest();
        if ($request->getBaseDn() === null) {
            $request->setBaseDn($this->options->getBaseDn() ?? null);
        }

        return parent::handleRequest($message);
    }

    /**
     * {@inheritDoc}
     */
    public function handleResponse(
        LdapMessageRequest $messageTo,
        LdapMessageResponse $messageFrom,
    ): ?LdapMessageResponse {
        $this->initializeSync($messageTo);

        try {
            do {
                $this->syncRequestControl->setCookie($this->session->getCookie());
                $searchDone = self::search(
                    $messageFrom,
                    $messageTo,
                    $this->queue,
                );
                // @todo This should be a configurable option or a specific exception...
                if ($this->isRefreshRequired($searchDone)) {
                    // We need to regenerate a search request / response with a new cookie...
                    $this->syncRequestControl->setCookie(
                        $searchDone
                            ->controls()
                            ->getByClass(SyncDoneControl::class)
                            ?->getCookie()
                    );
                    $messageTo = new LdapMessageRequest(
                        $this->queue->generateId(),
                        $this->syncRequest,
                        ...$messageFrom->controls()->toArray()
                    );
                    $messageFrom = $this->queue->sendMessage($messageTo)
                        ->getMessage($messageTo->getMessageId());
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
        /** @var SyncRequest $searchRequest */
        $searchRequest = $messageTo->getRequest();
        $this->syncRequest = $searchRequest;
        $this->syncRequestControl = $messageTo->controls()
            ->getByClass(SyncRequestControl::class) ?? throw new RuntimeException(sprintf(
                'Expected a "%s", but there is none.',
                SyncRequestControl::class,
            ));

        $this->session = new Session(
            mode: $this->syncRequestControl->getMode(),
            cookie: $this->syncRequestControl->getCookie(),
        );

        // We override these with our own, so save them here for now.
        $this->syncEntryHandler = $this->syncRequest->getEntryHandler();
        $this->syncReferralHandler = $this->syncRequest->getReferralHandler();
        $this->syncIdSetHandler = $this->syncRequest->getIdSetHandler();
        $this->cookieHandler = $this->syncRequest->getCookieHandler();

        $this->syncRequest->useEntryHandler($this->processSyncEntry(...));
        $this->syncRequest->useReferralHandler($this->processSyncReferral(...));
        $this->syncRequest->useIntermediateResponseHandler($this->processIntermediateResponse(...));
    }

    /**
     * We wrap the handlers with our own at the start of the sync process. This cleans it up so the request has the
     * original handlers at the end of the process again.
     */
    private function resetRequestHandlers(): void
    {
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
            $this->updateCookie($response->getCookie());
            $this->session->updatePhase(Session::PHASE_DELETE);
        } elseif ($response instanceof SyncRefreshPresent) {
            $this->updateCookie($response->getCookie());
            $this->session->updatePhase(Session::PHASE_PRESENT);
        } elseif ($response instanceof SyncNewCookie) {
            $this->updateCookie($response->getCookie());
        } elseif ($response instanceof SyncIdSet) {
            $this->updateCookie($response->getCookie());

            if ($this->syncIdSetHandler instanceof Closure) {
                call_user_func(
                    $this->syncIdSetHandler,
                    new SyncIdSetResult($messageFrom),
                    $this->session,
                );
            }
        }
    }

    private function isSyncComplete(LdapMessageResponse $response): bool
    {
        /** @var SearchResultDone $result */
        $result = $response->getResponse();
        $syncDone = $response->controls()
            ->getByClass(SyncDoneControl::class);

        if ($syncDone === null) {
            return true;
        }
        $this->updateCookie($syncDone->getCookie());

        return $result->getResultCode() === ResultCode::SUCCESS
            || $result->getResultCode() === ResultCode::CANCELED;
    }

    private function isRefreshRequired(LdapMessageResponse $response): bool
    {
        /** @var SearchResultDone $result */
        $result = $response->getResponse();

        return $result->getResultCode() === ResultCode::SYNCHRONIZATION_REFRESH_REQUIRED;
    }

    /**
     * Update the cookie in all the spots if it was actually returned and different from what we already have saved.
     * Some controls / requests will return the cookie, but they are not required to actually provide a value.
     */
    private function updateCookie(?string $cookie): void
    {
        if ($cookie === null || $this->session->getCookie() === $cookie) {
            return;
        }

        $this->syncRequestControl->setCookie($cookie);
        $this->session->updateCookie($cookie);

        if ($this->cookieHandler !== null) {
            call_user_func(
                $this->cookieHandler,
                $cookie
            );
        }
    }
}
