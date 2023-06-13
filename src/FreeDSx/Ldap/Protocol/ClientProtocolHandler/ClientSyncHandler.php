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

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshPresent;
use FreeDSx\Ldap\Operation\Response\SyncInfoMessage;
use FreeDSx\Ldap\Operation\Response\SyncResponse;
use FreeDSx\Ldap\Operation\Response\SyncResult;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Search\Result\ReferralResult;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Result\SyncReferralResult;
use FreeDSx\Ldap\Search\SyncHandlerInterface;

class ClientSyncHandler extends ClientBasicHandler
{
    private ?SyncHandlerInterface $syncHandler;

    private LdapMessageResponse $lastResponse;

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
        /** @var SyncRequest $searchRequest */
        $searchRequest = $messageTo->getRequest();
        $this->syncHandler = $searchRequest->getSyncHandler();

        return $this->handle(
            $messageTo,
            $queue,
        );
    }

    public function handle(
        LdapMessageRequest $messageTo,
        ClientQueue $queue,
    ): ?LdapMessageResponse {
        $initial = [];
        $updates = [];
        $present = [];
        $deleted = [];
        $cookie = '';

        $control = $messageTo->controls()->get(Control::OID_SYNC_REQUEST);
        if (!$control instanceof SyncRequestControl) {
            throw new RuntimeException('Expected a SyncRequestControl, but there is none.');
        }

        $syncDone = null;
        if ($this->isInitialPollRequest($control)) {
            $initial = $this->initialContent(
                $messageTo,
                $queue
            );
            $syncDone = $this->getSyncDoneControl($this->lastResponse);
            if ($syncDone === null) {
                throw new ProtocolException('Expected a SyncDoneControl, but none was received.');
            }
            $cookie = $syncDone->getCookie();
        } elseif ($this->isContentUpdatePoll($control)) {
            $updates = $this->persistStage(
                $queue,
                $messageTo,
                $control,
            );
            $syncDone = $this->getSyncDoneControl($this->lastResponse);

            if ($syncDone === null) {
                throw new ProtocolException('Expected a SyncDoneControl, but none was received.');
            }

            $cookie = $syncDone->getCookie();
            if (!$cookie) {
                $cookie = $control->getCookie();
            }
        }

        if ($this->isContentUpdatePoll($control) && $syncDone?->getRefreshDeletes()) {
            $deleted = $this->phaseDeleted(
                $queue,
                $messageTo
            );
        }

        return new LdapMessageResponse(
            $this->lastResponse->getMessageId(),
            new SyncResponse(
                $this->getLdapResult($this->lastResponse),
                (string) $cookie,
                $present,
                $deleted,
                $initial,
                $updates,
            ),
            ...$this->lastResponse->controls()->toArray()
        );
    }

    private function initialContent(
        LdapMessageRequest $messageTo,
        ClientQueue $queue
    ): array {
        $results = [];
        $isDone = false;

        foreach ($queue->getMessages($messageTo->getMessageId()) as $message) {
            $response = $message->getResponse();
            $syncResult = null;

            if ($response instanceof SearchResultEntry) {
                $syncResult = new SyncEntryResult(
                    new EntryResult($message)
                );
            } elseif ($response instanceof SearchResultReference) {
                $syncResult = new SyncReferralResult(
                    new ReferralResult($message)
                );
            } elseif ($response instanceof SearchResultDone) {
                $isDone = true;
            } else {
                throw new ProtocolException(
                    'Unexpected message encountered during initial content sync.'
                );
            }

            if ($syncResult && $this->syncHandler) {
                // need to change a bunch of this logic...
                // $this->syncHandler->initialPoll($syncResult);
            } elseif ($syncResult) {
                $results[] = $syncResult;
            }
            if ($isDone) {
                $this->lastResponse = $message;
                break;
            }
        }

        return $results;
    }

    private function phaseDeleted(
        ClientQueue $queue,
        LdapMessageRequest $messageTo
    ): array {
        $results = [];

        foreach ($queue->getMessages($messageTo->getMessageId()) as $message) {
            $response = $message->getResponse();

            if ($response instanceof SearchResultEntry) {
                $results[] = new SyncResult(
                    $response->getEntry(),
                    $this->getSyncStateControl($message),
                );
            } elseif ($response instanceof SearchResultReference) {
                $results[] = new SyncResult(
                    $response->getReferrals(),
                    $this->getSyncStateControl($message),
                );
            } elseif ($response instanceof SearchResultDone) {
                $this->lastResponse = $message;
                break;
            }
        }

        return $results;
    }

    private function persistStage(
        ClientQueue $queue,
        LdapMessageRequest $messageTo,
        SyncRequestControl $syncRequest,
    ): array {
        $isDone = false;
        $syncInfoDelete = null;
        $syncInfoPresent = null;
        $syncNewCookie = null;
        $message = null;

        $syncResults = [];
        do {
            foreach ($queue->getMessages($messageTo->getMessageId()) as $message) {
                $this->lastResponse = $message;
                $response = $message->getResponse();

                if ($response instanceof SyncInfoMessage) {
                    $this->processSyncInfo(
                        $queue,
                        $messageTo,
                        $message,
                        $response,
                        $syncRequest,
                    );

                    continue;
                }

                if ($response instanceof SearchResultEntry) {
                    $syncResults[] = new SyncResult(
                        $response->getEntry(),
                        $this->getSyncStateControl($message)
                    );
                } elseif ($response instanceof SearchResultReference) {
                    $syncResults[] = new SyncResult(
                        $response->getReferrals(),
                        $this->getSyncStateControl($message)
                    );
                } elseif ($response instanceof SearchResultDone) {
                    $isDone = true;
                    break;
                }
            }
        } while (!$isDone);

        return $syncResults;
    }

    private function isInitialPollRequest(SyncRequestControl $control): bool
    {
        return empty($control->getCookie())
            && $control->getMode() === SyncRequestControl::MODE_REFRESH_ONLY;
    }

    private function isContentUpdatePoll(SyncRequestControl $control): bool
    {
        return !empty($control->getCookie());
    }

    private function getSyncStateControl(LdapMessageResponse $response): ?SyncStateControl
    {
        return $response->controls()
            ->getByClass(SyncStateControl::class);
    }

    private function getSyncDoneControl(LdapMessageResponse $response): ?SyncDoneControl
    {
        return $response->controls()
            ->getByClass(SyncDoneControl::class);
    }

    private function getLdapResult(LdapMessageResponse $response): LdapResult
    {
        $result = $response->getResponse();

        if (!$result instanceof LdapResult) {
            throw new RuntimeException(sprintf(
                'Expected an LdapResult, but received "%s".',
                $result::class
            ));
        }

        return $result;
    }

    private function processSyncInfo(
        ClientQueue $queue,
        LdapMessageRequest $messageTo,
        LdapMessageResponse $messageFrom,
        SyncInfoMessage $response,
        SyncRequestControl $syncRequest,
    ): void {
        if ($response instanceof SyncRefreshDelete) {
            $syncInfoDelete = $response;
            $syncRequest->setCookie($syncInfoDelete->getCookie());
            $queue->sendMessage($messageTo);
        } elseif ($response instanceof SyncRefreshPresent) {
            $syncInfoPresent = $response;
            $syncRequest->setCookie($syncInfoPresent->getCookie());
            $queue->sendMessage($messageTo);
        } elseif ($response instanceof SyncNewCookie) {
            $syncNewCookie = $response;
            $syncRequest->setCookie($syncNewCookie->getCookie());
        } elseif ($response instanceof SyncIdSet) {
            $syncResult = new SyncIdSetResult($messageFrom);
            // need to implement handling for this...
        }
    }
}
