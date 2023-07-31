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
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
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
        ?FilterInterface $filter = null
    ) {
        $this->client = $client;
        $this->syncRequest = Operations::sync($filter);
        $this->controls = new ControlBag();
    }

    /**
     * Use the "continue" cancel strategy. When this is enabled, sync handlers will continue to receive any messages
     * from the point of cancellation until the server acknowledges the cancellation. By default these messages would be
     * discarded.
     */
    public function useContinueOnCancel(): self
    {
        $this->syncRequest->useCancelStrategy(SearchRequest::CANCEL_CONTINUE);

        return $this;
    }

    /**
     * Define a closure that handles cookie updates.
     *
     * **Note**: The cookie might not actually be updated if nothing changes between syncs.
     */
    public function useCookieHandler(Closure $handler): self
    {
        $this->syncRequest->useCookieHandler($handler);

        return $this;
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
        $this->syncRequest->useReferralHandler($handler);

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
        $this->syncRequest->useIdSetHandler($handler);

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
     * Set the cookie to use as part of the sync operation. This should be a cookie from a previous sync. To retrieve
     * the cookie during the sync use {@see Session::getCookie()} from the Sync session in the handlers.
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
     * In a listen based sync, the server sends updates of entries that are changed after the initial refresh content is
     * determined. The sync continues indefinitely until the connection is terminated or the sync is canceled.
     *
     * **Note**: The LdapClient should be instantiated with no timeout via {@see ClientOptions::setTimeoutRead(-1)}.
     *           Otherwise, the listen operation will terminate due to a network timeout.
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

        $this->client->sendAndReceive(
            $this->syncRequest,
            Controls::syncRequest(
                $this->cookie,
                $mode,
            ),
            Controls::manageDsaIt(),
            ...$this->controls->toArray(),
        );
    }
}
