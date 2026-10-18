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

namespace Tests\Performance\FreeDSx\Ldap\Compare;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Seed\PersonSeedEntries;
use Tests\Support\FreeDSx\Ldap\Seed\SeedDn;
use Throwable;

/**
 * Seeds and cleans up a throwaway bench subtree in a live external LDAP target.
 *
 * Note: Active Directory needs a different schema and is not supported here.
 */
final class TargetBench
{
    /**
     * Kept under the smallest default size limit the benched servers enforce.
     */
    private const CLEANUP_PAGE_SIZE = 500;

    /**
     * Seeded on every person but withheld from every run identity by each side's access control.
     */
    private const WITHHELD_DESCRIPTION = 'userpassword';

    public readonly string $benchBaseDn;

    public readonly string $writeBaseDn;

    private LdapClient $client;

    private bool $bound = false;

    public function __construct(
        private readonly string $host,
        private readonly int $port,
        private readonly string $bindDn,
        private readonly string $bindPassword,
        private readonly string $rootBaseDn,
        private readonly string $benchOu = 'freedsx-bench',
        private readonly string $peopleOu = 'people',
    ) {
        $this->benchBaseDn = "ou={$this->benchOu},{$this->rootBaseDn}";
        $this->writeBaseDn = "ou={$this->peopleOu},{$this->benchBaseDn}";
        $this->client = $this->buildClient();
    }

    public function compareDn(): string
    {
        return "cn=alice,{$this->writeBaseDn}";
    }

    public function mailDomain(): string
    {
        if (preg_match_all('/dc=([^,]+)/i', $this->rootBaseDn, $matches) === 0) {
            return 'example.com';
        }

        return implode(
            '.',
            array_map('strtolower', $matches[1]),
        );
    }

    /**
     * Proves the server is reachable and the credentials work, so a bad side is reported before anything is seeded.
     */
    public function preflight(): void
    {
        $this->bindIfNeeded();
    }

    public function ensureSubtree(): void
    {
        $this->bindIfNeeded();

        $this->ensureOrganizationalUnit(
            $this->benchBaseDn,
            $this->benchOu,
        );
        $this->ensureOrganizationalUnit(
            $this->writeBaseDn,
            $this->peopleOu,
        );
    }

    public function seed(
        int $seedEntries,
        int $seedGroups = 0,
        int $seedGroupSize = 0,
    ): void {
        $this->ensureSubtree();

        $mailDomain = $this->mailDomain();

        $this->ensurePerson(
            $this->compareDn(),
            'alice',
            'Alice',
            "alice@{$mailDomain}",
            '1',
        );

        foreach ($this->people()->people($seedEntries) as $person) {
            $this->createOrIgnoreExists($person);
        }

        $this->ensureGroups($seedGroups, $seedGroupSize);
    }

    /**
     * @throws RuntimeException
     */
    public function assertBindable(
        string $bindDn,
        string $bindPassword,
    ): void {
        $client = $this->buildClient();

        try {
            $client->bind(
                $bindDn,
                $bindPassword,
            );
            $client->unbind();
        } catch (Throwable $e) {
            throw new RuntimeException(sprintf(
                'Unable to bind to LDAP target at %s:%d as the run identity %s: %s',
                $this->host,
                $this->port,
                $bindDn,
                $e->getMessage(),
            ), 0, $e);
        }
    }

    /**
     * Fails when the identity the workload runs as may not add and delete an entry, which the write ops need.
     *
     * @throws RuntimeException
     */
    public function assertWritableBy(
        string $bindDn,
        string $bindPassword,
    ): void {
        $probeDn = "cn=freedsx-bench-probe,{$this->writeBaseDn}";
        $this->removeIfPresent($probeDn);
        $client = $this->buildClient();
        $probe = new Entry(
            $probeDn,
            new Attribute(
                'objectClass',
                'inetOrgPerson',
            ),
            new Attribute(
                'cn',
                'freedsx-bench-probe',
            ),
            new Attribute(
                'sn',
                'Probe',
            ),
        );

        try {
            $client->bind(
                $bindDn,
                $bindPassword,
            );
            $client->create($probe);
            $client->delete($probeDn);
            $client->unbind();
        } catch (Throwable $e) {
            throw new RuntimeException(sprintf(
                'The run identity %s may not write below %s on %s:%d: %s',
                $bindDn,
                $this->writeBaseDn,
                $this->host,
                $this->port,
                $e->getMessage(),
            ), 0, $e);
        }
    }

    /**
     * What access control got wrong when an identity reads a seeded person's own attributes by name.
     *
     * @return list<string>
     * @throws OperationException
     */
    public function accessProblemsFor(
        string $bindDn,
        string $bindPassword,
    ): array {
        $expected = $this->seededDescriptions();
        $client = $this->buildClient();
        $client->bind(
            $bindDn,
            $bindPassword,
        );

        try {
            $person = $client->read(
                "cn=seed-1,{$this->writeBaseDn}",
                $expected,
            );
        } finally {
            $client->unbind();
        }

        $visible = array_map(
            static fn(Attribute $attribute): string => strtolower($attribute->getDescription()),
            $person?->getAttributes() ?? [],
        );
        $problems = [];

        if (in_array(self::WITHHELD_DESCRIPTION, $visible, true)) {
            $problems[] = sprintf(
                'returned %s to its run identity',
                self::WITHHELD_DESCRIPTION,
            );
        }

        $missing = array_diff(
            $expected,
            [self::WITHHELD_DESCRIPTION],
            $visible,
        );

        if ($missing !== []) {
            $problems[] = sprintf(
                'withheld %s from its run identity',
                implode(
                    ', ',
                    $missing,
                ),
            );
        }

        return $problems;
    }

    public function cleanup(): void
    {
        // The seed connection may have gone idle and been dropped during the run, so reconnect for a reliable teardown.
        $this->reconnect();

        $dns = $this->subtreeDns();

        usort(
            $dns,
            fn(string $a, string $b) => substr_count($b, ',') <=> substr_count($a, ','),
        );

        foreach ($dns as $dn) {
            try {
                $this->client->delete($dn);
            } catch (Throwable) {
            }
        }
    }

    public function close(): void
    {
        if (!$this->bound) {
            return;
        }

        try {
            $this->client->unbind();
        } catch (Throwable) {
        }

        $this->bound = false;
    }

    /**
     * Groups the group ops work against, seeded after the entries they name.
     */
    private function ensureGroups(
        int $seedGroups,
        int $seedGroupSize,
    ): void {
        if ($seedGroups < 1) {
            return;
        }
        $members = [];

        for ($i = 1; $i <= $seedGroupSize; $i++) {
            $members[] = "cn=seed-{$i},{$this->writeBaseDn}";
        }

        for ($g = 0; $g < $seedGroups; $g++) {
            $this->createOrIgnoreExists(new Entry(
                "cn=load-group-{$g},{$this->writeBaseDn}",
                new Attribute('objectClass', 'groupOfNames'),
                new Attribute('cn', "load-group-{$g}"),
                new Attribute('member', ...$members),
            ));
        }
    }

    /**
     * A seeded subtree outgrows the size limit a single search is capped at, so it is collected a page at a time.
     *
     * @return list<string>
     * @throws OperationException
     */
    private function subtreeDns(): array
    {
        $paging = $this->client->paging(
            Operations::search(Filters::present('objectClass'))
                ->base($this->benchBaseDn)
                ->useSubtreeScope(),
            self::CLEANUP_PAGE_SIZE,
        );

        $dns = [];

        try {
            while ($paging->hasEntries()) {
                foreach ($paging->getEntries() as $entry) {
                    $dns[] = (string) $entry->getDn();
                }
            }
        } catch (OperationException $e) {
            if ($e->getCode() !== ResultCode::NO_SUCH_OBJECT) {
                throw $e;
            }
        }

        return $dns;
    }

    /**
     * A probe left behind by an earlier run that kept its subtree would otherwise fail the next probe's add.
     */
    private function removeIfPresent(string $dn): void
    {
        $this->bindIfNeeded();

        try {
            $this->client->delete($dn);
        } catch (OperationException $e) {
            if ($e->getCode() !== ResultCode::NO_SUCH_OBJECT) {
                throw $e;
            }
        }
    }

    private function people(): PersonSeedEntries
    {
        return new PersonSeedEntries(
            dn: new SeedDn(
                people: $this->writeBaseDn,
                groups: "ou=groups,{$this->benchBaseDn}",
                mailDomain: $this->mailDomain(),
            ),
        );
    }

    /**
     * @return list<string>
     */
    private function seededDescriptions(): array
    {
        $descriptions = [];

        foreach ($this->people()->people(1) as $person) {
            foreach ($person->getAttributes() as $attribute) {
                $descriptions[] = strtolower($attribute->getDescription());
            }
        }

        return $descriptions;
    }

    private function buildClient(): LdapClient
    {
        return new LdapClient(
            (new ClientOptions())
                ->setServers([$this->host])
                ->setPort($this->port)
                ->setTransport('tcp')
                ->setTimeoutConnect(5)
                ->setTimeoutRead(30),
        );
    }

    private function reconnect(): void
    {
        try {
            $this->client->unbind();
        } catch (Throwable) {
        }

        $this->client = $this->buildClient();
        $this->bound = false;
        $this->bindIfNeeded();
    }

    private function bindIfNeeded(): void
    {
        if ($this->bound) {
            return;
        }

        try {
            $this->client->bind($this->bindDn, $this->bindPassword);
        } catch (Throwable $e) {
            throw new RuntimeException(sprintf(
                'Unable to bind to LDAP target at %s:%d as %s: %s',
                $this->host,
                $this->port,
                $this->bindDn,
                $e->getMessage(),
            ), 0, $e);
        }

        $this->bound = true;
    }

    private function ensureOrganizationalUnit(
        string $dn,
        string $ou,
    ): void {
        $entry = new Entry(
            $dn,
            new Attribute('objectClass', 'organizationalUnit'),
            new Attribute('ou', $ou),
        );

        $this->createOrIgnoreExists($entry);
    }

    private function ensurePerson(
        string $dn,
        string $cn,
        string $sn,
        string $mail,
        string $uidNumber,
    ): void {
        $entry = new Entry(
            $dn,
            new Attribute('objectClass', 'inetOrgPerson', 'extensibleObject'),
            new Attribute('cn', $cn),
            new Attribute('sn', $sn),
            new Attribute('mail', $mail),
            new Attribute('uidNumber', $uidNumber),
        );

        $this->createOrIgnoreExists($entry);
    }

    private function createOrIgnoreExists(Entry $entry): void
    {
        try {
            $this->client->create($entry);
        } catch (OperationException $e) {
            if ($e->getCode() === ResultCode::ENTRY_ALREADY_EXISTS) {
                return;
            }

            throw $e;
        }
    }
}
