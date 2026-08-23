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

namespace Tests\Performance\FreeDSx\Ldap\Workload;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Paging;
use LogicException;
use Tests\Performance\FreeDSx\Ldap\Config;
use Tests\Performance\FreeDSx\Ldap\Stats\StatsCollector;
use Throwable;

/**
 * Generates load from a single forked client process against the server.
 */
final class Worker
{
    private readonly string $compareDn;

    private readonly string $mailDomain;

    /**
     * @var list<string> DNs known to exist at startup; used by search-read / search-eq.
     */
    private readonly array $fixedReadDns;

    /**
     * @var list<string> DNs this worker added and has not yet deleted; modify/delete pick from here.
     */
    private array $ownedDns = [];

    private int $addSeq = 0;

    /**
     * @var ?Paging Active paged search; each search-paged op pulls one page, restarting when the walk is exhausted.
     */
    private ?Paging $paging = null;

    public function __construct(
        private readonly int $workerId,
        private readonly Config $config,
        private readonly WorkloadMix $mix,
        private readonly StatsCollector $stats,
        private readonly ?int $opsCap,
    ) {
        $this->compareDn = 'cn=alice,' . $this->config->writeBase;
        $this->mailDomain = $this->deriveMailDomain($this->config->baseDn);
        $this->fixedReadDns = [
            $this->config->baseDn,
            $this->config->writeBase,
            $this->compareDn,
        ];
    }

    /**
     * Open the connection and bind; throws on failure so the parent can fail the readiness barrier.
     */
    public function connect(): LdapClient
    {
        $client = $this->buildClient();
        $client->bind(
            $this->config->bindDn,
            $this->config->bindPassword,
        );

        return $client;
    }

    /**
     * Drive the workload until the deadline (or ops cap), enabling recording once past the warmup mark.
     */
    public function run(
        LdapClient $client,
        float $recordStart,
        ?float $deadline,
    ): void {
        $recording = false;
        $iterations = 0;

        while ($this->shouldContinue($deadline, $iterations)) {
            if (!$recording && microtime(true) >= $recordStart) {
                $this->stats->startRecording();
                $recording = true;
            }

            $this->runOne($client);
            $iterations++;
        }
    }

    public function disconnect(LdapClient $client): void
    {
        try {
            $client->unbind();
        } catch (Throwable) {
        }
    }

    private function deriveMailDomain(string $baseDn): string
    {
        if (preg_match_all('/dc=([^,]+)/i', $baseDn, $matches) === 0) {
            return 'example.com';
        }

        return implode('.', array_map('strtolower', $matches[1]));
    }

    private function shouldContinue(?float $deadline, int $iterations): bool
    {
        if ($deadline !== null && microtime(true) >= $deadline) {
            return false;
        }

        if ($this->opsCap !== null && $iterations >= $this->opsCap) {
            return false;
        }

        return true;
    }

    private function runOne(LdapClient $client): void
    {
        $op = $this->mix->pick();
        $effective = $this->resolveEffectiveOp($op);

        $start = hrtime(true);

        try {
            $this->dispatch($client, $effective);
            $this->stats->recordSuccess($op, hrtime(true) - $start);
        } catch (OperationException $e) {
            if ($e->getCode() === ResultCode::SIZE_LIMIT_EXCEEDED) {
                $this->stats->recordSuccess($op, hrtime(true) - $start);

                return;
            }

            $this->stats->recordError($op, $e::class);
        } catch (Throwable $e) {
            $this->stats->recordError($op, $e::class);
        }
    }

    private function resolveEffectiveOp(string $op): string
    {
        if (($op === 'modify' || $op === 'delete') && $this->ownedDns === []) {
            $this->stats->recordSubstitution($op, 'add');

            return 'add';
        }

        return $op;
    }

    private function dispatch(LdapClient $client, string $op): void
    {
        match ($op) {
            'bind' => $this->doBind($client),
            'search-read' => $this->doSearchRead($client),
            'search-eq' => $this->doSearchEq($client),
            'search-sub' => $this->doSearchSub($client),
            'search-substr' => $this->doSearchSubstr($client),
            'search-suffix' => $this->doSearchSuffix($client),
            'search-range' => $this->doSearchRange($client),
            'search-list' => $this->doSearchList($client),
            'search-and' => $this->doSearchAnd($client),
            'search-or' => $this->doSearchOr($client),
            'search-sort' => $this->doSearchSort($client),
            'search-paged' => $this->doSearchPaged($client),
            'compare' => $this->doCompare($client),
            'add' => $this->doAdd($client),
            'modify' => $this->doModify($client),
            'delete' => $this->doDelete($client),
            default => throw new LogicException("Unknown load-test op: {$op}"),
        };
    }

    private function doBind(LdapClient $client): void
    {
        $client->bind(
            $this->config->bindDn,
            $this->config->bindPassword,
        );
    }

    private function doSearchRead(LdapClient $client): void
    {
        $request = $this->newSearch(Filters::present('objectClass'))
            ->base($this->randomReadDn())
            ->useBaseScope();

        $client->search($request);
    }

    private function doSearchEq(LdapClient $client): void
    {
        $request = $this->newSearch($this->randomEqualityFilter())
            ->base($this->config->baseDn)
            ->useSubtreeScope();

        $client->search($request);
    }

    private function doSearchSub(LdapClient $client): void
    {
        $request = $this->newSearch($this->searchValueFilter())
            ->base($this->config->baseDn)
            ->useSubtreeScope();
        $this->applySearchSizeLimit($request);

        $client->search($request);
    }

    private function doSearchList(LdapClient $client): void
    {
        $request = $this->newSearch(Filters::equal('objectClass', 'inetOrgPerson'))
            ->base($this->config->writeBase)
            ->useSingleLevelScope();
        $this->applySearchSizeLimit($request);

        $client->search($request);
    }

    /**
     * Applies the shared search size limit so list and sub cap at the same count for an apples-to-apples comparison.
     */
    private function applySearchSizeLimit(SearchRequest $request): void
    {
        if ($this->config->searchSizeLimit > 0) {
            $request->sizeLimit($this->config->searchSizeLimit);
        }
    }

    private function searchValueFilter(): FilterInterface
    {
        return $this->config->seedEntries > 0
            ? Filters::startsWith('cn', $this->config->searchValue)
            : Filters::present('cn');
    }

    private function doSearchSubstr(LdapClient $client): void
    {
        $filter = $this->config->seedEntries >= 100
            ? Filters::contains('cn', (string) mt_rand(100, $this->config->seedEntries))
            : Filters::contains('cn', 'eed');

        $client->search(
            $this->newSearch($filter)
                ->base($this->config->baseDn)
                ->useSubtreeScope(),
        );
    }

    private function doSearchSuffix(LdapClient $client): void
    {
        $filter = $this->config->seedEntries > 0
            ? Filters::endsWith('cn', "d-{$this->randomSeedIdx()}")
            : Filters::endsWith('cn', 'e');

        $client->search(
            $this->newSearch($filter)
                ->base($this->config->baseDn)
                ->useSubtreeScope(),
        );
    }

    private function doSearchRange(LdapClient $client): void
    {
        $threshold = $this->config->seedEntries > 0
            ? 1000 + max(1, $this->config->seedEntries - 99)
            : 1000;

        $client->search(
            $this->newSearch(Filters::greaterThanOrEqual('uidNumber', (string) $threshold))
                ->base($this->config->baseDn)
                ->useSubtreeScope(),
        );
    }

    /**
     * Composed AND with a broad leaf and a selective leaf; streams off the selective leaf, then PHP-verifies the rest.
     */
    private function doSearchAnd(LdapClient $client): void
    {
        $filter = Filters::and(
            Filters::equal('objectClass', 'inetOrgPerson'),
            $this->randomEqualityFilter(),
        );

        $client->search(
            $this->newSearch($filter)
                ->base($this->config->baseDn)
                ->useSubtreeScope(),
        );
    }

    /**
     * Composed OR of two selective leaves; exercises the OR-composite path, which streaming does not yet cover.
     */
    private function doSearchOr(LdapClient $client): void
    {
        $filter = Filters::or(
            $this->randomEqualityFilter(),
            $this->randomEqualityFilter(),
        );

        $client->search(
            $this->newSearch($filter)
                ->base($this->config->baseDn)
                ->useSubtreeScope(),
        );
    }

    /**
     * Server-side sort over a selective subset (a realistic sorted search filters first), size-limited to a display page.
     */
    private function doSearchSort(LdapClient $client): void
    {
        $request = $this->newSearch($this->searchValueFilter())
            ->base($this->config->baseDn)
            ->useSubtreeScope();

        if ($this->config->searchSortSizeLimit > 0) {
            $request->sizeLimit($this->config->searchSortSizeLimit);
        }

        $client->search(
            $request,
            Controls::sort('sn'),
        );
    }

    /**
     * Fetches ONE page of a paged (RFC 2696) subtree search per op, so each sample is a single page's latency; the
     * page size matches the shared search size limit, making a page directly comparable to a one-shot search.
     */
    private function doSearchPaged(LdapClient $client): void
    {
        if ($this->paging === null || !$this->paging->hasEntries()) {
            $this->paging = $client->paging(
                $this->newSearch($this->searchValueFilter())
                    ->base($this->config->baseDn)
                    ->useSubtreeScope(),
                $this->config->searchSizeLimit > 0
                    ? $this->config->searchSizeLimit
                    : null,
            );
        }

        try {
            $this->paging->getEntries();
        } catch (Throwable $e) {
            // Drop the cursor so the next op starts a fresh walk; re-throw so the outer handler records the outcome.
            $this->paging = null;

            throw $e;
        }
    }

    /**
     * Builds a search request, applying the configured attribute selection so the return path can be varied.
     */
    private function newSearch(FilterInterface $filter): SearchRequest
    {
        $request = Operations::search($filter);
        $attributes = $this->config->searchAttributes;

        if ($attributes !== null && strcasecmp($attributes, 'ALL') !== 0) {
            $request->select(...array_map(
                'trim',
                explode(
                    ',',
                    $attributes,
                ),
            ));
        }

        if ($this->config->attributesOnly) {
            $request->setAttributesOnly(true);
        }

        return $request;
    }

    private function randomSeedIdx(): int
    {
        return mt_rand(
            1,
            $this->config->seedEntries,
        );
    }

    private function randomReadDn(): string
    {
        if ($this->config->seedEntries > 0 && mt_rand(1, 100) <= 80) {
            $idx = mt_rand(1, $this->config->seedEntries);

            return "cn=seed-{$idx}," . $this->config->writeBase;
        }

        return $this->fixedReadDns[array_rand($this->fixedReadDns)];
    }

    private function randomEqualityFilter(): FilterInterface
    {
        if ($this->config->seedEntries > 0 && mt_rand(1, 100) <= 80) {
            $idx = mt_rand(1, $this->config->seedEntries);

            return mt_rand(0, 1) === 0
                ? Filters::equal('cn', "seed-{$idx}")
                : Filters::equal('mail', "seed-{$idx}@{$this->mailDomain}");
        }

        return mt_rand(0, 1) === 0
            ? Filters::equal('cn', 'alice')
            : Filters::equal('mail', "alice@{$this->mailDomain}");
    }

    private function doCompare(LdapClient $client): void
    {
        $client->compare($this->compareDn, 'mail', "alice@{$this->mailDomain}");
    }

    private function doAdd(LdapClient $client): void
    {
        $seq = ++$this->addSeq;
        $cn = "load-w{$this->workerId}-{$seq}";
        $dn = "cn={$cn}," . $this->config->writeBase;

        $client->create(new Entry(
            $dn,
            new Attribute('cn', $cn),
            new Attribute('objectClass', 'inetOrgPerson', 'extensibleObject'),
            new Attribute('sn', 'Load'),
            new Attribute('uidNumber', (string) $seq),
        ));

        $this->ownedDns[] = $dn;
    }

    private function doModify(LdapClient $client): void
    {
        $dn = $this->ownedDns[array_rand($this->ownedDns)];

        $request = Operations::modify(
            $dn,
            Change::replace('uidNumber', (string) mt_rand(1, 1_000_000)),
        );

        $client->send($request);
    }

    private function doDelete(LdapClient $client): void
    {
        $idx = array_rand($this->ownedDns);
        $dn = $this->ownedDns[$idx];

        $client->delete($dn);

        array_splice($this->ownedDns, $idx, 1);
    }

    private function buildClient(): LdapClient
    {
        return new LdapClient(
            (new ClientOptions())
                ->setServers([$this->config->host])
                ->setPort($this->config->port)
                ->setTransport('tcp')
                ->setTimeoutConnect(5)
                ->setTimeoutRead(30),
        );
    }
}
