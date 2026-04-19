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
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use LogicException;
use Swoole\Coroutine\Channel;
use Tests\Performance\FreeDSx\Ldap\Config;
use Tests\Performance\FreeDSx\Ldap\Stats\StatsCollector;
use Throwable;

/**
 * Generates load in a single Swoole coroutine.
 */
final class Worker
{
    private const BIND_DN = 'cn=user,dc=foo,dc=bar';

    private const BIND_PASSWORD = '12345';

    private const SEARCH_BASE = 'dc=foo,dc=bar';

    private const WRITE_BASE = 'ou=people,dc=foo,dc=bar';

    private const COMPARE_DN = 'cn=alice,ou=people,dc=foo,dc=bar';

    /**
     * @var list<string> DNs known to exist at startup; used by search-read / search-eq.
     */
    private const FIXED_READ_DNS = [
        'dc=foo,dc=bar',
        'cn=user,dc=foo,dc=bar',
        'ou=people,dc=foo,dc=bar',
        'cn=alice,ou=people,dc=foo,dc=bar',
    ];

    /**
     * @var list<string> DNs this worker added and has not yet deleted; modify/delete pick from here.
     */
    private array $ownedDns = [];

    private int $addSeq = 0;

    public function __construct(
        private readonly int $workerId,
        private readonly Config $config,
        private readonly WorkloadMix $mix,
        private readonly StatsCollector $stats,
        private readonly Channel $readyBarrier,
        private readonly Channel $startSignal,
        private readonly ?int $opsCap,
    ) {
    }

    public function run(): void
    {
        $client = $this->buildClient();

        try {
            $client->bind(self::BIND_DN, self::BIND_PASSWORD);
        } catch (Throwable $e) {
            $this->readyBarrier->push(false);

            throw $e;
        }

        $this->readyBarrier->push(true);

        $signal = $this->startSignal->pop();
        if ($signal === false) {
            $this->cleanup($client);

            return;
        }

        $deadline = is_float($signal) ? $signal : null;

        $iterations = 0;
        while ($this->shouldContinue($deadline, $iterations)) {
            $this->runOne($client);
            $iterations++;
        }

        $this->cleanup($client);
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
            'search-list' => $this->doSearchList($client),
            'compare' => $this->doCompare($client),
            'add' => $this->doAdd($client),
            'modify' => $this->doModify($client),
            'delete' => $this->doDelete($client),
            default => throw new LogicException("Unknown load-test op: {$op}"),
        };
    }

    private function doBind(LdapClient $client): void
    {
        $client->bind(self::BIND_DN, self::BIND_PASSWORD);
    }

    private function doSearchRead(LdapClient $client): void
    {
        $request = Operations::search(Filters::present('objectClass'))
            ->base($this->randomReadDn())
            ->useBaseScope();

        $client->search($request);
    }

    private function doSearchEq(LdapClient $client): void
    {
        $request = Operations::search($this->randomEqualityFilter())
            ->base(self::SEARCH_BASE)
            ->useSubtreeScope();

        $client->search($request);
    }

    private function doSearchSub(LdapClient $client): void
    {
        $filter = $this->config->seedEntries > 0
            ? Filters::startsWith('cn', 'seed-')
            : Filters::startsWith('cn', '');

        $request = Operations::search($filter)
            ->base(self::SEARCH_BASE)
            ->useSubtreeScope();

        $client->search($request);
    }

    private function doSearchList(LdapClient $client): void
    {
        $request = Operations::search(Filters::equal('objectClass', 'inetOrgPerson'))
            ->base(self::WRITE_BASE)
            ->useSubtreeScope();

        $client->search($request);
    }

    private function randomReadDn(): string
    {
        if ($this->config->seedEntries > 0 && mt_rand(1, 100) <= 80) {
            $idx = mt_rand(1, $this->config->seedEntries);

            return "cn=seed-{$idx},ou=people,dc=foo,dc=bar";
        }

        return self::FIXED_READ_DNS[array_rand(self::FIXED_READ_DNS)];
    }

    private function randomEqualityFilter(): FilterInterface
    {
        if ($this->config->seedEntries > 0 && mt_rand(1, 100) <= 80) {
            $idx = mt_rand(1, $this->config->seedEntries);

            return mt_rand(0, 1) === 0
                ? Filters::equal('cn', "seed-{$idx}")
                : Filters::equal('mail', "seed-{$idx}@foo.bar");
        }

        return mt_rand(0, 1) === 0
            ? Filters::equal('cn', 'alice')
            : Filters::equal('mail', 'alice@foo.bar');
    }

    private function doCompare(LdapClient $client): void
    {
        $client->compare(self::COMPARE_DN, 'mail', 'alice@foo.bar');
    }

    private function doAdd(LdapClient $client): void
    {
        $seq = ++$this->addSeq;
        $cn = "load-w{$this->workerId}-{$seq}";
        $dn = "cn={$cn}," . self::WRITE_BASE;

        $client->create(new Entry(
            $dn,
            new Attribute('cn', $cn),
            new Attribute('objectClass', 'inetOrgPerson'),
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
            Change::replace('uidNumber', (string) mt_rand(1, 1_000_000))
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

    private function cleanup(LdapClient $client): void
    {
        try {
            $client->unbind();
        } catch (Throwable) {
        }
    }

    private function buildClient(): LdapClient
    {
        return new LdapClient(
            (new ClientOptions())
                ->setServers([$this->config->host])
                ->setPort($this->config->port)
                ->setTransport('tcp')
                ->setTimeoutConnect(5)
                ->setTimeoutRead(30)
        );
    }
}
