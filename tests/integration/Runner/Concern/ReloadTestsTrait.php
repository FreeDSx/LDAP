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

namespace Tests\Integration\FreeDSx\Ldap\Runner\Concern;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

trait ReloadTestsTrait
{
    public function testAReloadedAccessPolicyReachesASessionAlreadyOpen(): void
    {
        $this->requirePosix();
        $flagFile = $this->makeFlagFile();
        $this->createServerProcess(
            'tcp',
            ['--log', '--reload-flag-file=' . $flagFile],
        );
        $session = $this->buildClient('tcp');
        $session->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        try {
            $before = $session->read('cn=user,dc=foo,dc=bar');
            file_put_contents(
                $flagFile,
                'deny-sn',
            );
            $this->reloadServer();
            $after = $session->read('cn=user,dc=foo,dc=bar');

            self::assertTrue($before?->has('sn'));
            self::assertFalse($after?->has('sn'));
        } finally {
            @unlink($flagFile);
        }
    }

    public function testAPagedSearchContinuesUnderTheReloadedAccessPolicy(): void
    {
        $this->requirePosix();
        $flagFile = $this->makeFlagFile();
        $this->createServerProcess(
            'tcp',
            ['--log', '--reload-flag-file=' . $flagFile, '--entries=10'],
        );
        $session = $this->buildClient('tcp');
        $session->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
        $paging = $session->paging(
            Operations::search(Filters::startsWith('cn', 'entry-'))->base('dc=foo,dc=bar'),
            5,
        );

        try {
            $before = $paging->getEntries()->toArray();
            file_put_contents(
                $flagFile,
                'deny-sn',
            );
            $this->reloadServer();
            $after = $paging->getEntries()->toArray();

            self::assertSame(
                [5, 5],
                [count($before), count($this->withSn($before))],
            );
            self::assertSame(
                [5, 0],
                [count($after), count($this->withSn($after))],
            );
        } finally {
            @unlink($flagFile);
        }
    }

    /**
     * @param Entry[] $entries
     * @return Entry[]
     */
    private function withSn(array $entries): array
    {
        return array_filter(
            $entries,
            static fn(Entry $entry): bool => $entry->has('sn'),
        );
    }
}
