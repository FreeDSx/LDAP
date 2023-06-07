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

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshPresent;
use FreeDSx\Ldap\Operation\Response\SyncResponse;
use FreeDSx\Ldap\Operation\Response\SyncResult;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\SyncHandlerInterface;

class ClientSyncProtocolHandler
{
    private ClientQueue $queue;

    private SyncRequestControl $syncRequest;

    private LdapMessageRequest $messageTo;

    private ?SyncHandlerInterface $syncHandler;

    private LdapMessageResponse $lastResponse;

    public function __construct(
        ClientQueue $queue,
        LdapMessageRequest $messageTo,
        SyncRequestControl $syncRequest
    ) {
        $this->queue = $queue;
        $this->messageTo = $messageTo;
        $this->syncRequest = $syncRequest;
        $this->syncHandler = $syncRequest->getSyncHandler();
    }

    public function handle(): ?LdapMessageResponse
    {
        $initial = [];
        $updates = [];
        $present = [];
        $deleted = [];
        $cookie = '';

        $syncDone = null;
        if ($this->isInitialPollRequest()) {
            $initial = $this->initialContent();
            $syncDone = $this->lastResponse->controls()->get(Control::OID_SYNC_DONE);
            if (!$syncDone instanceof SyncDoneControl) {
                throw new ProtocolException('Expected a SyncDoneControl, but none was received.');
            }
            $cookie = $syncDone->getCookie();
        } elseif ($this->isContentUpdatePoll()) {
            $updates = $this->persistStage();
            $syncDone = $this->lastResponse->controls()->get(Control::OID_SYNC_DONE);
            if (!$syncDone instanceof SyncDoneControl) {
                throw new ProtocolException('Expected a SyncDoneControl, but none was received.');
            }
            $cookie = $syncDone->getCookie();
            if (!$cookie) {
                $cookie = $this->syncRequest->getCookie();
            }
        }

        if ($this->isContentUpdatePoll() && $syncDone && $syncDone->getRefreshDeletes()) {
            #$deleted = $this->phaseDeleted();
        }

        return new LdapMessageResponse(
            $this->lastResponse->getMessageId(),
            new SyncResponse(
                $this->lastResponse->getResponse(),
                $cookie,
                $present,
                $deleted,
                $initial,
                $updates
            ),
            ...$this->lastResponse->controls()->toArray()
        );
    }

    private function initialContent() : array
    {
        $results = [];
        $isDone = false;

        /** @var LdapMessageResponse $message */
        foreach ($this->queue->getMessages($this->messageTo->getMessageId()) as $message) {
            $response = $message->getResponse();
            $syncResult = null;

            if ($response instanceof SearchResultEntry) {
                $syncResult = new SyncResult(
                    $response->getEntry(),
                    $message->controls()->get(Control::OID_SYNC_STATE)
                );
            } elseif ($response instanceof SearchResultReference) {
                $syncResult = new SyncResult(
                    $response->getReferrals(),
                    $message->controls()->get(Control::OID_SYNC_STATE)
                );
            } elseif ($response instanceof SearchResultDone) {
                $isDone = true;
            } else {
                throw new ProtocolException('Unexpected message encountered during initial content sync.');
            }

            if ($syncResult && $this->syncHandler) {
                $this->syncHandler->initialPoll($syncResult);
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

    private function phaseDeleted(): array
    {
        /** @var LdapMessageResponse $message */
        foreach ($this->queue->getMessages($this->messageTo->getMessageId()) as $message) {
            $response = $message->getResponse();
            $syncResult = null;

            if ($response instanceof SearchResultEntry) {
                $syncResult = new SyncResult(
                    $response->getEntry(),
                    $message->controls()->get(Control::OID_SYNC_STATE)
                );
            } elseif ($response instanceof SearchResultReference) {
                $syncResult = new SyncResult(
                    $response->getReferrals(),
                    $message->controls()->get(Control::OID_SYNC_STATE)
                );
            } elseif ($response instanceof SearchResultDone) {
                $this->lastResponse = $message;
                break;
            }
        }

        return [];
    }

    private function phasePresent(): array
    {
    }

    private function persistStage(): array
    {
        $isDone = false;
        $syncInfoDelete = null;
        $syncInfoPresent = null;
        $syncNewCookie = null;
        $message = null;

        $syncResults = [];
        do {
            /** @var LdapMessageResponse $message */
            foreach ($this->queue->getMessages($this->messageTo->getMessageId()) as $message) {
                $response = $message->getResponse();

                if ($response instanceof SyncRefreshDelete) {
                    $syncInfoDelete = $response;
                    $this->syncRequest->setCookie($syncInfoDelete->getCookie());
                    $this->queue->sendMessage($this->messageTo);
                } elseif ($response instanceof SyncRefreshPresent) {
                    $syncInfoPresent = $response;
                    $this->syncRequest->setCookie($syncInfoPresent->getCookie());
                    $this->queue->sendMessage($this->messageTo);
                } elseif ($response instanceof SyncNewCookie) {
                    $syncNewCookie = $response;
                    $this->syncRequest->setCookie($syncNewCookie->getCookie());
                } elseif ($response instanceof SyncIdSet) {

                } else {
                    if ($response instanceof SearchResultEntry) {
                        $syncResults[] = new SyncResult(
                            $response->getEntry(),
                            $message->controls()->get(Control::OID_SYNC_STATE)
                        );
                    } elseif ($response instanceof SearchResultReference) {
                        $syncResults[] = new SyncResult(
                            $response->getReferrals(),
                            $message->controls()->get(Control::OID_SYNC_STATE)
                        );
                    } elseif ($response instanceof SearchResultDone) {
                        $isDone = true;
                        break;
                    }
                }
            }
        } while (!$isDone);
        $this->lastResponse = $message;

        return $syncResults;
    }

    private function isInitialPollRequest() : bool
    {
        return empty($this->syncRequest->getCookie())
            && $this->syncRequest->getMode() === SyncRequestControl::MODE_REFRESH_ONLY;
    }

    private function isContentUpdatePoll() : bool
    {
        return !empty($this->syncRequest->getCookie());
    }
}
