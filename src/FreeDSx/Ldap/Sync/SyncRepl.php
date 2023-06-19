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

namespace FreeDSx\Ldap\Sync;

use Closure;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;

/**
 * A helper class for an LDAP Content Synchronization Operation, described by RFC 4533.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 * @see https://tools.ietf.org/html/rfc4533
 */
class SyncRepl
{
    private SyncRequest $syncRequest;

    private LdapClient $client;

    private ControlBag $controls;

    private ?string $cookie = null;

    public function __construct(
        LdapClient $client,
        ?SyncRequest $syncRequest = null
    ) {
        $this->client = $client;
        $this->syncRequest = $syncRequest ?? Operations::sync();
        $this->controls = new ControlBag();
    }

    /**
     * Define a closure that handles normal entries received during the sync process.
     *
     * Note: If you do not define a closure, they will be ignored by the sync.
     */
    public function useEntryHandler(Closure $handler): self
    {
        $this->syncRequest->useEntryHandler($handler);

        return $this;
    }

    /**
     * Define a closure that handles referrals received during the sync process.
     *
     * Note: If you do not define a closure, they will be ignored by the sync.
     */
    public function useReferralHandler(Closure $handler): self
    {
        $this->syncRequest->useEntryHandler($handler);

        return $this;
    }

    /**
     * Define a closure that handles IdSets received during the sync process.
     *
     * IdSets are arrays of entry UUIDs that represent a large set of changes, such as deletes, but do not contain other
     * information about the records (such as the full Entry object).
     *
     * Note: If you do not define a closure, they will be ignored by the sync.
     */
    public function useIdSetHandler(Closure $handler): self
    {
        $this->syncRequest->useEntryHandler($handler);

        return $this;
    }

    public function useSyncRequest(SyncRequest $syncRequest): self
    {
        $this->syncRequest = $syncRequest;

        return $this;
    }

    /**
     * A convenience method to set the filter to use for this sync. This can also be set using {@see self::request()}.
     */
    public function useFilter(FilterInterface $filter): self
    {
        $this->syncRequest->setFilter($filter);

        return $this;
    }

    /**
     * Set the cookie to use as part of the sync operation. This should be a cookie from a previous sync. To retrieve the
     * cookie during the sync use {@see Session::getCookie()} from the Sync session in the handlers.
     */
    public function useCookie(?string $cookie): self
    {
        $this->cookie = $cookie;

        return $this;
    }

    /**
     * Any additional controls to get sent as part of the sync process.
     */
    public function controls(): ControlBag
    {
        return $this->controls;
    }

    /**
     * The {@see SyncRequest} in use for this sync. Has other methods on it that control the overall search.
     */
    public function request(): SyncRequest
    {
        return $this->syncRequest;
    }

    /**
     * The cookie related to this sync session. It is updated as the sync is preformed. It can be saved / re-used in
     * future sync operations.
     */
    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    /**
     * In a listen based sync, the server sends updates of entries that are changed after the initial refresh content is
     * determined. The sync continues indefinitely until the connection is terminated or the sync is canceled.
     *
     * **Note**: The LdapClient should be instantiated with no timeout via {@see ClientOptions::setTimeoutRead(-1)}. Otherwise, the listen operation will terminate due to a network timeout.
     */
    public function listen(Closure $entryHandler = null): void
    {
        $this->sync(
            mode: SyncRequestControl::MODE_REFRESH_AND_PERSIST,
            entryHandler: $entryHandler,
        );
    }

    /**
     * A poll based sync gets any initial content / updates and then ends.
     *
     * If a cookie is provided, then it is a poll for content update. If no cookie is provided, then it is a poll for
     * content update. To provide a cookie from a previous poll {@see self::useCookie()}.
     */
    public function poll(Closure $entryHandler = null): void
    {
        $this->sync(
            mode: SyncRequestControl::MODE_REFRESH_ONLY,
            entryHandler: $entryHandler,
        );
    }

    private function sync(
        int $mode,
        ?Closure $entryHandler,
    ): void {
        if ($entryHandler) {
            $this->useEntryHandler($entryHandler);
        }

        $this->getResponseAndUpdateCookie(
            Controls::syncRequest(
                $this->cookie,
                $mode,
            ),
            Controls::manageDsaIt()
        );
    }

    private function getResponseAndUpdateCookie(Control ...$controls): void
    {
        $messageResponse = $this->client->sendAndReceive(
            $this->syncRequest,
            ...$controls,
            ...$this->controls->toArray(),
        );

        $searchDone = $messageResponse->controls()
            ->getByClass(SyncDoneControl::class);

        if ($searchDone === null) {
            throw new ProtocolException(sprintf(
                'Expected a "%s" control, but none was received.',
                SyncDoneControl::class,
            ));
        }

        $this->cookie = $searchDone->getCookie();
    }
}
