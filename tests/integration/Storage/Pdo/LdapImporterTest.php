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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Pdo;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class LdapImporterTest extends TestCase
{
    private const BASE = 'dc=example,dc=com';

    private const TEAM = 'cn=Team,dc=example,dc=com';

    private const ALICE = 'cn=Alice,dc=example,dc=com';

    private LdapImporter $subject;

    private ReadEntryInterface $reader;

    protected function setUp(): void
    {
        $container = Container::forServer(TestServerOptions::sqlite());
        $this->subject = $container->get(LdapImporter::class);
        $this->reader = $container->get(ReadEntryInterface::class);
    }

    public function test_a_load_naming_an_entry_it_never_stores_is_refused_naming_the_entry_and_attribute(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->expectExceptionMessage(
            'The attribute "uniquemember" of entry "cn=Team,dc=example,dc=com" names an entry that does not exist.',
        );

        $this->subject->importEntries([
            $this->base(),
            $this->team("cn=Ghost,dc=example,dc=com#'0101'B"),
        ]);
    }

    public function test_a_load_naming_an_entry_it_stores_later_links_it(): void
    {
        $this->subject->importEntries([
            $this->base(),
            $this->team(self::ALICE . "#'0101'B"),
            Entry::fromArray(
                self::ALICE,
                [
                    'objectClass' => ['person'],
                    'cn' => ['Alice'],
                    'sn' => ['Alice'],
                ],
            ),
        ]);

        self::assertSame(
            [self::ALICE . "#'0101'B"],
            $this->reader->find(new Dn(self::TEAM))?->get('uniqueMember')?->getValues(),
        );
    }

    private function base(): Entry
    {
        return Entry::fromArray(
            self::BASE,
            ['dc' => ['example']],
        );
    }

    private function team(string $uniqueMember): Entry
    {
        return Entry::fromArray(
            self::TEAM,
            [
                'objectClass' => ['groupOfUniqueNames'],
                'cn' => ['Team'],
                'uniqueMember' => [$uniqueMember],
            ],
        );
    }
}
