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

namespace Tests\Integration\FreeDSx\Ldap\Storage;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\SubtreeDeleteProgressControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * A subtree delete larger than one request may remove, run against SQLite alone since seeding it is slow.
 */
final class LdapSubtreeDeleteLimitTest extends ServerTestCase
{
    private const BASE_DN = 'ou=people,dc=foo,dc=bar';

    private const ENTRIES_PER_REQUEST = 25_000;

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    public function testASubtreeBeyondTheRequestLimitKeepsItsBaseUntilTheDeleteIsResubmitted(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--seed-entries=' . (self::ENTRIES_PER_REQUEST + 10)],
        );
        $this->authenticateAdmin();

        try {
            $this->deleteSubtree();
            self::fail('The delete should have stopped at the request limit.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getCode(),
            );
            self::assertSame(
                self::ENTRIES_PER_REQUEST,
                $this->deletedIn($e->controls()),
            );
        }
        $this->authenticateUser();
        $remaining = $this->entriesLeft();
        self::assertNotNull($this->ldapClient()->read(self::BASE_DN));

        $response = $this->asAdmin(fn(): ?LdapMessageResponse => $this->deleteSubtree());

        self::assertSame(
            $remaining,
            $this->deletedIn($response?->controls() ?? new ControlBag()),
        );
        self::assertNull($this->ldapClient()->read(self::BASE_DN));
    }

    protected function serverStartupSeconds(): int
    {
        return 60;
    }

    private function deleteSubtree(): ?LdapMessageResponse
    {
        return $this->ldapClient()->send(
            Operations::delete(self::BASE_DN),
            Controls::subtreeDelete(),
        );
    }

    private function entriesLeft(): int
    {
        return $this->ldapClient()->search(
            Operations::search(
                Filters::present('objectClass'),
                '1.1',
            )->base(self::BASE_DN)->useSubtreeScope(),
        )->count();
    }

    private function deletedIn(ControlBag $controls): ?int
    {
        $progress = $controls->get(Control::OID_SUBTREE_DELETE_PROGRESS);

        return $progress instanceof SubtreeDeleteProgressControl
            ? $progress->getDeleted()
            : null;
    }
}
