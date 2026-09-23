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
    /**
     * Values per membership page, matching the server's default cap so a page and a range slice are the same size.
     */
    private const MEMBERSHIP_PAGE = 1500;

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

    /**
     * The group this worker owns; each worker gets its own, so one worker's members never collide with another's.
     */
    private readonly string $groupDn;

    /**
     * @var list<string> Seeded DNs not currently in the group; group-add-member draws from here.
     */
    private array $spareMembers;

    /**
     * @var list<string> DNs this worker put in the group; group-del-member draws from here.
     */
    private array $addedMembers = [];

    private int $addSeq = 0;

    /**
     * @var ?Paging Active paged search; each search-paged op pulls one page, restarting when the walk is exhausted.
     */
    private ?Paging $paging = null;

    /**
     * @var ?Paging The same, over the entries a group names.
     */
    private ?Paging $membership = null;

    /**
     * Where the next membership slice starts, so an op reads one slice rather than the whole group.
     */
    private int $rangeAt = 0;

    public function __construct(
        private readonly int $workerId,
        private readonly Config $config,
        private readonly WorkloadMix $mix,
        private readonly StatsCollector $stats,
        private readonly ?int $opsCap,
    ) {
        $this->compareDn = 'cn=alice,' . $this->config->writeBase;
        $this->mailDomain = $this->deriveMailDomain($this->config->baseDn);
        $this->groupDn = $this->config->seedGroups > 0
            ? sprintf(
                'cn=load-group-%d,%s',
                $this->workerId % $this->config->seedGroups,
                $this->config->writeBase,
            )
            : '';
        $this->spareMembers = $this->buildSpareMembers();
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
            $entries = $this->dispatch($client, $effective);
            $this->stats->recordSuccess($op, hrtime(true) - $start, $entries);
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

        $substitute = $this->groupSubstitute($op);

        if ($substitute !== null) {
            $this->stats->recordSubstitution($op, $substitute);

            return $substitute;
        }

        return $op;
    }

    private function groupSubstitute(string $op): ?string
    {
        if ($op === 'group-add-member' && $this->spareMembers === []) {
            return $this->addedMembers === []
                ? 'group-reset'
                : 'group-del-member';
        }

        if ($op === 'group-del-member' && $this->addedMembers === []) {
            return $this->spareMembers === []
                ? 'group-reset'
                : 'group-add-member';
        }

        return null;
    }

    /**
     * @return int Entries the op saw, which every op not meant to return any reports as none.
     */
    private function dispatch(LdapClient $client, string $op): int
    {
        return match ($op) {
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
            'group-add-member' => $this->doGroupAddMember($client),
            'group-del-member' => $this->doGroupDelMember($client),
            'group-reset' => $this->doGroupReset($client),
            'group-read-range' => $this->doGroupReadRange($client),
            'search-memberof' => $this->doSearchMemberOf($client),
            default => throw new LogicException("Unknown load-test op: {$op}"),
        };
    }

    private function doBind(LdapClient $client): int
    {
        $client->bind(
            $this->config->bindDn,
            $this->config->bindPassword,
        );

        return 0;
    }

    private function doSearchRead(LdapClient $client): int
    {
        $request = $this->newSearch(Filters::present('objectClass'))
            ->base($this->randomReadDn())
            ->useBaseScope();

        return count($client->search($request));
    }

    private function doSearchEq(LdapClient $client): int
    {
        $request = $this->newSearch($this->randomEqualityFilter())
            ->base($this->config->baseDn)
            ->useSubtreeScope();

        return count($client->search($request));
    }

    private function doSearchSub(LdapClient $client): int
    {
        $request = $this->newSearch($this->searchValueFilter())
            ->base($this->config->baseDn)
            ->useSubtreeScope();
        $this->applySearchSizeLimit($request);

        return count($client->search($request));
    }

    private function doSearchList(LdapClient $client): int
    {
        $request = $this->newSearch(Filters::equal('objectClass', 'inetOrgPerson'))
            ->base($this->config->writeBase)
            ->useSingleLevelScope();
        $this->applySearchSizeLimit($request);

        return count($client->search($request));
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

    private function doSearchSubstr(LdapClient $client): int
    {
        $filter = $this->config->seedEntries >= 100
            ? Filters::contains('cn', (string) mt_rand(100, $this->config->seedEntries))
            : Filters::contains('cn', 'eed');

        return count($client->search(
            $this->newSearch($filter)
                ->base($this->config->baseDn)
                ->useSubtreeScope(),
        ));
    }

    private function doSearchSuffix(LdapClient $client): int
    {
        $filter = $this->config->seedEntries > 0
            ? Filters::endsWith('cn', "d-{$this->randomSeedIdx()}")
            : Filters::endsWith('cn', 'e');

        return count($client->search(
            $this->newSearch($filter)
                ->base($this->config->baseDn)
                ->useSubtreeScope(),
        ));
    }

    private function doSearchRange(LdapClient $client): int
    {
        $threshold = $this->config->seedEntries > 0
            ? 1000 + max(1, $this->config->seedEntries - 99)
            : 1000;

        return count($client->search(
            $this->newSearch(Filters::greaterThanOrEqual('uidNumber', (string) $threshold))
                ->base($this->config->baseDn)
                ->useSubtreeScope(),
        ));
    }

    /**
     * Composed AND with a broad leaf and a selective leaf; streams off the selective leaf, then PHP-verifies the rest.
     */
    private function doSearchAnd(LdapClient $client): int
    {
        $filter = Filters::and(
            Filters::equal('objectClass', 'inetOrgPerson'),
            $this->randomEqualityFilter(),
        );

        return count($client->search(
            $this->newSearch($filter)
                ->base($this->config->baseDn)
                ->useSubtreeScope(),
        ));
    }

    /**
     * Composed OR of two selective leaves; exercises the OR-composite path, which streaming does not yet cover.
     */
    private function doSearchOr(LdapClient $client): int
    {
        $filter = Filters::or(
            $this->randomEqualityFilter(),
            $this->randomEqualityFilter(),
        );

        return count($client->search(
            $this->newSearch($filter)
                ->base($this->config->baseDn)
                ->useSubtreeScope(),
        ));
    }

    /**
     * Server-side sort over a selective subset (a realistic sorted search filters first), size-limited to a display page.
     */
    private function doSearchSort(LdapClient $client): int
    {
        $request = $this->newSearch($this->searchValueFilter())
            ->base($this->config->baseDn)
            ->useSubtreeScope();

        if ($this->config->searchSortSizeLimit > 0) {
            $request->sizeLimit($this->config->searchSortSizeLimit);
        }

        return count($client->search(
            $request,
            Controls::sort('sn'),
        ));
    }

    /**
     * Fetches ONE page of a paged (RFC 2696) subtree search per op, so each sample is a single page's latency; the
     * page size matches the shared search size limit, making a page directly comparable to a one-shot search.
     */
    private function doSearchPaged(LdapClient $client): int
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
            return count($this->paging->getEntries());
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

    private function doCompare(LdapClient $client): int
    {
        $client->compare($this->compareDn, 'mail', "alice@{$this->mailDomain}");

        return 0;
    }

    private function doAdd(LdapClient $client): int
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

        return 0;
    }

    private function doModify(LdapClient $client): int
    {
        $dn = $this->ownedDns[array_rand($this->ownedDns)];

        $request = Operations::modify(
            $dn,
            Change::replace('uidNumber', (string) mt_rand(1, 1_000_000)),
        );

        $client->send($request);

        return 0;
    }

    private function doGroupAddMember(LdapClient $client): int
    {
        $dn = $this->drawMember($this->spareMembers);

        $client->send(Operations::modify(
            $this->groupDn,
            Change::add('member', $dn),
        ));

        $this->addedMembers[] = $dn;

        return 0;
    }

    private function doGroupDelMember(LdapClient $client): int
    {
        $dn = $this->drawMember($this->addedMembers);

        $client->send(Operations::modify(
            $this->groupDn,
            Change::delete('member', $dn),
        ));

        $this->spareMembers[] = $dn;

        return 0;
    }

    private function doGroupReadRange(LdapClient $client): int
    {
        $entry = $client->read(
            $this->groupDn,
            [sprintf('member;range=%d-*', $this->rangeAt)],
        );
        $held = null;

        foreach ($entry?->getAttributes() ?? [] as $attribute) {
            if (Attribute::normalizeName($attribute->getDescription()) === 'member') {
                $held = $attribute;
            }
        }

        // Named to the end, or named plainly, means nothing is left behind it.
        $more = $held !== null && !str_ends_with($held->getDescription(), '-*')
            && $held->getDescription() !== 'member';
        $values = count($held?->getValues() ?? []);

        $this->rangeAt = $more
            ? $this->rangeAt + $values
            : 0;

        return $values;
    }

    private function doSearchMemberOf(LdapClient $client): int
    {
        if ($this->membership === null || !$this->membership->hasEntries()) {
            // Names no attribute, since a membership is the DNs, which is all ranging the group's own values gives.
            $this->membership = $client->paging(
                Operations::search(
                    Filters::equal('memberOf', $this->groupDn),
                    SearchRequest::ATTRIBUTES_NONE,
                )
                    ->base($this->config->baseDn)
                    ->useSubtreeScope(),
                self::MEMBERSHIP_PAGE,
            );
        }

        try {
            return count($this->membership->getEntries());
        } catch (Throwable $e) {
            $this->membership = null;

            throw $e;
        }
    }

    private function doGroupReset(LdapClient $client): int
    {
        $client->send(Operations::modify(
            $this->groupDn,
            Change::replace('member', ...$this->seededMembers()),
        ));

        $this->spareMembers = $this->buildSpareMembers();
        $this->addedMembers = [];

        return 0;
    }

    /**
     * @param list<string> $pool
     */
    private function drawMember(array &$pool): string
    {
        $dn = array_pop($pool);

        if ($dn === null) {
            throw new LogicException('A group op drew from an empty member pool.');
        }

        return $dn;
    }

    /**
     * @return list<string>
     */
    private function buildSpareMembers(): array
    {
        $clients = max($this->config->clients, 1);
        $spare = [];

        for ($i = $this->config->seedGroupSize + 1; $i <= $this->config->seedEntries; $i++) {
            if ($i % $clients === $this->workerId % $clients) {
                $spare[] = "cn=seed-{$i}," . $this->config->writeBase;
            }
        }

        return $spare;
    }

    /**
     * @return list<string>
     */
    private function seededMembers(): array
    {
        $members = [];

        for ($i = 1; $i <= $this->config->seedGroupSize; $i++) {
            $members[] = "cn=seed-{$i}," . $this->config->writeBase;
        }

        return $members;
    }

    private function doDelete(LdapClient $client): int
    {
        $idx = array_rand($this->ownedDns);
        $dn = $this->ownedDns[$idx];

        $client->delete($dn);

        array_splice($this->ownedDns, $idx, 1);

        return 0;
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
