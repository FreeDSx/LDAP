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

namespace Tests\Integration\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Throwable;

final class LdapServerTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer('ldap-server', 'tcp');
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();
    }

    public function testItCanBind(): void
    {
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
        $this->assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function testItRejectsBindWithIncorrectCredentials(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bind(
            'cn=fake,dc=foo,dc=bar',
            'also-fake',
        );
    }

    public function testItPerformsAnAdd(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=added,dc=foo,dc=bar',
            ['cn' => 'added', 'sn' => 'Test', 'objectClass' => 'inetOrgPerson'],
        ));

        $result = $this->ldapClient()->read('cn=added,dc=foo,dc=bar');
        $this->assertNotNull($result);
        $this->assertSame(
            'Test',
            $result->get('sn')?->firstValue(),
        );
    }

    public function testItPerformsDelete(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=todelete,dc=foo,dc=bar',
            ['cn' => 'todelete', 'sn' => 'Delete', 'objectClass' => 'inetOrgPerson'],
        ));
        $this->ldapClient()->delete('cn=todelete,dc=foo,dc=bar');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);
        $this->ldapClient()->readOrFail('cn=todelete,dc=foo,dc=bar');
    }

    public function testItPerformsModify(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=tomodify,dc=foo,dc=bar',
            ['cn' => 'tomodify', 'sn' => 'Before', 'mail' => 'before@example.com', 'objectClass' => 'inetOrgPerson'],
        ));

        $changes = Entry::fromArray('cn=tomodify,dc=foo,dc=bar', []);
        $changes->set('sn', 'After');
        $changes->add('mail', 'added@example.com');
        $this->ldapClient()->update($changes);

        $result = $this->ldapClient()->read('cn=tomodify,dc=foo,dc=bar');
        $this->assertNotNull($result);
        $this->assertSame(
            'After',
            $result->get('sn')?->firstValue(),
        );
        $this->assertContains(
            'added@example.com',
            $result->get('mail')?->getValues() ?? [],
        );
    }

    public function testItPerformsSearches(): void
    {
        $this->authenticateUser();

        $result = $this->ldapClient()->read('cn=user,dc=foo,dc=bar');
        $this->assertNotNull($result);
        $this->assertSame(
            'cn=user,dc=foo,dc=bar',
            $result->getDn()->toString(),
        );
    }

    public function testItCanPerformCompare(): void
    {
        $this->authenticateUser();

        $this->assertTrue(
            $this->ldapClient()->compare(
                'cn=user,dc=foo,dc=bar',
                'cn',
                'user',
            ),
        );
    }

    public function testItCanModifyDn(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=tomove,dc=foo,dc=bar',
            ['cn' => 'tomove', 'sn' => 'Move', 'objectClass' => 'inetOrgPerson'],
        ));
        $this->ldapClient()->rename(
            'cn=tomove,dc=foo,dc=bar',
            'cn=moved',
            true,
        );

        $result = $this->ldapClient()->read('cn=moved,dc=foo,dc=bar');
        $this->assertNotNull($result);
        $this->assertSame(
            'cn=moved,dc=foo,dc=bar',
            $result->getDn()->toString(),
        );
    }

    public function testItCanRetrieveTheRootDSE(): void
    {
        $rootDse = $this->ldapClient()->read();

        $this->assertNotNull($rootDse);
        $this->assertSame(
            [
                'objectClass' => [
                    'top',
                ],
                'namingContexts' => [
                    'dc=foo,dc=bar',
                ],
                'subschemaSubentry' => [
                    'cn=Subschema',
                ],
                'supportedControl' => [
                    '1.2.840.113556.1.4.319',
                    '1.2.840.113556.1.4.473',
                    '1.3.6.1.4.1.4203.666.5.12',
                    '2.16.840.1.113730.3.4.18',
                    '2.16.840.1.113730.3.4.2',
                    '1.3.6.1.1.12',
                    '1.3.6.1.1.13.1',
                    '1.3.6.1.1.13.2',
                    '1.2.840.113556.1.4.805',
                    '1.3.6.1.4.1.4203.1.9.1.1',
                ],
                'supportedExtension' => [
                    '1.3.6.1.4.1.4203.1.11.3',
                    '1.3.6.1.4.1.4203.1.11.1',
                    '1.3.6.1.1.8',
                    '1.3.6.1.4.1.66207.1.1.1',
                    '1.3.6.1.4.1.1466.20037',
                ],
                'supportedFeatures' => [
                    '1.3.6.1.4.1.4203.1.5.1',
                    '1.3.6.1.4.1.4203.1.5.3',
                ],
                'supportedLDAPVersion' => [
                    '3',
                ],
                'vendorName' => [
                    'FreeDSx',
                ],
            ],
            $rootDse->toArray(),
        );
    }

    public function testThatOperationCompareRequireAuthentication(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->compare(
            'dc=foo,dc=bar',
            'foo',
            'bar',
        );
    }

    public function testThatOperationSearchRequireAuthentication(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->read('dc=foo,dc=bar');
    }

    public function testThatOperationAddRequireAuthentication(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->create(Entry::fromArray(
            'dc=foo,dc=bar',
            ['foo' => 'bar'],
        ));
    }

    public function testThatOperationDeleteRequireAuthentication(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->delete('dc=foo,dc=bar');
    }

    public function testThatOperationModifyRequireAuthentication(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $entry = Entry::fromArray('cn=foo,dc=foo,dc=bar');
        $entry->add('email', 'foo@bar.local');

        $this->ldapClient()->update($entry);
    }

    public function testThatOperationModifyDnRequireAuthentication(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->move(
            'dc=foo,dc=bar',
            'cn=here, dc=foo, dc=bar',
        );
    }

    public function testWhoAmIWhenAuthenticated(): void
    {
        $this->authenticateUser();
        $output = $this->ldapClient()->whoami();

        $this->assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $output,
        );
    }

    public function testWhoAmIWhenNotAuthenticated(): void
    {
        $output = $this->ldapClient()->whoami();

        $this->assertNull($output);
    }

    public function testItCanHandlingPaging(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--entries=5000', '--max-search-lookthrough=0']);
        $this->authenticateUser();

        $allEntries = [];
        $iterations = 0;

        $search = Operations::search(Filters::raw('(foo=*)'))->base('dc=foo,dc=bar');
        $paging = $this->ldapClient()->paging($search);

        while ($paging->hasEntries()) {
            $iterations++;
            $entries = $paging->getEntries(100);
            $allEntries = array_merge(
                $allEntries,
                $entries->toArray(),
            );
        }

        $this->assertSame(50, $iterations);
        $this->assertCount(5000, $allEntries);
    }

    public function testPagedSearchHonorsAGenerousSeparatePagedLookthroughLimit(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', [
            '--entries=5000',
            '--max-search-lookthrough=10',
            '--max-search-paged-lookthrough=100000',
        ]);
        $this->authenticateUser();

        $search = Operations::search(Filters::raw('(foo=*)'))->base('dc=foo,dc=bar');
        $paging = $this->ldapClient()->paging($search);

        $count = 0;
        while ($paging->hasEntries()) {
            $count += count($paging->getEntries(500)->toArray());
        }

        $this->assertSame(
            5000,
            $count,
        );
    }

    public function testPagedSearchFallsBackToRegularLookthroughWhenPagedUnset(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', [
            '--entries=5000',
            '--max-search-lookthrough=10',
            '--max-search-paged-lookthrough=0',
        ]);
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $search = Operations::search(Filters::raw('(foo=*)'))->base('dc=foo,dc=bar');
        $paging = $this->ldapClient()->paging($search);
        while ($paging->hasEntries()) {
            $paging->getEntries(500);
        }
    }

    public function testPerIdentityRuleAppliesAuthenticatedLookthrough(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', [
            '--entries=50',
            '--max-search-lookthrough=5000',
            '--authenticated-lookthrough=5',
        ]);
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->search(
            Operations::search(Filters::raw('(foo=*)'))->base('dc=foo,dc=bar')->useSubtreeScope(),
        );
    }

    public function testItDoesASearchWhenPagingIsNotMarkedAsCritical(): void
    {
        $this->authenticateUser();

        $search = Operations::search(Filters::raw('(cn=user)'))->base('dc=foo,dc=bar');
        $paging = $this->ldapClient()->paging($search);
        $result = $paging->getEntries();

        $this->assertFalse($paging->hasEntries());
        $this->assertNotEmpty($result->toArray());
    }

    public function testItCanStartTLSThenStillPerformOperations(): void
    {
        $this->ldapClient()->startTls();
        $result = $this->ldapClient()->read();

        $this->assertNotNull($result);
    }

    public function testItCanRunOverSSLOnly(): void
    {
        $this->stopServer();
        $this->createServerProcess('ssl');

        $result = $this->ldapClient()->read('');
        $this->assertNotNull($result);
    }

    public function testItKeepsAnSSLConnectionAliveWhenALaterConnectionEnds(): void
    {
        $this->stopServer();
        $this->createServerProcess('ssl');

        $established = $this->ldapClient();
        $established->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        $later = $this->buildClient('ssl');
        $later->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
        $later->unbind();

        // Give the connection handler the moment it needs to end before the established one is used again.
        usleep(250_000);

        $this->assertNotNull($established->read(''));
    }

    public function testItCanRunOverUnixSocket(): void
    {
        $this->stopServer();
        $this->createServerProcess('unix');

        $result = $this->ldapClient()->read('');
        $this->assertNotNull($result);
    }

    public function testItRefusesASimpleBindInTheClearWhenConfidentialityIsRequired(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--require-confidentiality=bind']);

        try {
            $this->ldapClient()->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
            $this->fail('Expected the bind to be refused.');
        } catch (BindException $e) {
            $this->assertSame(
                ResultCode::CONFIDENTIALITY_REQUIRED,
                $e->getCode(),
            );
        }
    }

    public function testItAcceptsTheSameBindAfterStartTLS(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--require-confidentiality=bind']);

        $this->ldapClient()->startTls();
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        $this->assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function testItAcceptsABindOverSSLWhenConfidentialityIsRequired(): void
    {
        $this->stopServer();
        $this->createServerProcess('ssl', ['--require-confidentiality=bind']);

        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        $this->assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function testAUnixSocketSatisfiesTheConfidentialityRequirement(): void
    {
        $this->stopServer();
        $this->createServerProcess('unix', ['--require-confidentiality=bind']);

        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        $this->assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function testRequiringAllOperationsRefusesASearchInTheClear(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--require-confidentiality=all']);

        try {
            $this->ldapClient()->read('');
            $this->fail('Expected the search to be refused.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::CONFIDENTIALITY_REQUIRED,
                $e->getCode(),
            );
        }
    }

    public function testRequiringAllOperationsStillPermitsStartTLS(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--require-confidentiality=all']);

        $this->ldapClient()->startTls();
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        $this->assertNotNull($this->ldapClient()->read(''));
    }

    public function testAMalformedDnIsAnsweredRatherThanEndingTheSession(): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->send(Operations::rename(
                'garbage-no-equals',
                'cn=x',
                true,
            ));
            $this->fail('Expected the rename to be refused.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }

        // The session must survive: a malformed DN is one operation failing, not a protocol error.
        $this->assertNotNull($this->ldapClient()->read(''));
    }

    public function testAnUnescapedCommaInANewRdnIsRefused(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create($this->personEntry('comma-src'));

        try {
            $this->ldapClient()->send(Operations::rename(
                'cn=comma-src,dc=foo,dc=bar',
                new Rdn('cn', 'Smith, John'),
                true,
            ));
            $this->fail('Expected the rename to be refused.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }

        $this->assertNotNull($this->ldapClient()->read('cn=comma-src,dc=foo,dc=bar'));
    }

    public function testAnAddWithAMalformedDnIsAnsweredRatherThanEndingTheSession(): void
    {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->send(Operations::add(Entry::fromArray('garbage-no-equals', [
                'objectClass' => ['inetOrgPerson'],
                'cn' => ['x'],
                'sn' => ['y'],
            ])));
            $this->fail('Expected the add to be refused.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }

        $this->assertNotNull($this->ldapClient()->read(''));
    }

    public function testASearchWithAMalformedBaseDnReportsNoSuchObject(): void
    {
        $this->authenticateAdmin();

        // The search path only normalizes, which never decomposes the DN, so there is nothing to reject.
        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('garbage-no-equals')
                    ->useSubtreeScope(),
            );
            $this->fail('Expected the search to be refused.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::NO_SUCH_OBJECT,
                $e->getCode(),
            );
        }
    }

    public function testItCanHandleMultipleClients(): void
    {
        $this->ldapClient()->read();
        $client2 = $this->getClient($this->ldapClient()->getOptions());

        $result = $client2->read();
        $this->assertNotNull($result);
    }

    public function testAnonymousBindSucceeds(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', ['--allow-anonymous']);

        $response = $this->ldapClient()
            ->send(Operations::bindAnonymously())
            ?->getResponse();

        $this->assertInstanceOf(
            BindResponse::class,
            $response,
        );
        $this->assertSame(
            0,
            $response->getResultCode(),
        );
    }

    public function testRenameWithoutDeleteKeepsOldRdn(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray(
            'cn=torenameold,dc=foo,dc=bar',
            [
                'cn' => 'torenameold',
                'sn' => 'RenameOld',
                'objectClass' => 'inetOrgPerson',
            ],
        ));
        $this->ldapClient()->rename(
            'cn=torenameold,dc=foo,dc=bar',
            'cn=torenamednew',
            false,
        );

        $result = $this->ldapClient()->read('cn=torenamednew,dc=foo,dc=bar', ['cn']);
        $this->assertNotNull($result);
        $cn = $result->get('cn');
        $this->assertNotNull($cn);
        $this->assertContains(
            'torenameold',
            $cn->getValues(),
        );
        $this->assertContains(
            'torenamednew',
            $cn->getValues(),
        );
    }

    public function testSetOptionsForceDisconnectsClient(): void
    {
        $this->authenticateUser();
        $this->ldapClient()->setOptions(
            options: new ClientOptions(),
            forceDisconnect: true,
        );

        $this->assertFalse($this->ldapClient()->isConnected());
    }

    public function testItCanEndPagingEarly(): void
    {
        $this->authenticateUser();

        $search = Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar');
        $paging = $this->ldapClient()->paging($search);

        $paging->getEntries(1);
        $this->assertTrue($paging->hasEntries());

        $paging->end();
        $this->assertFalse($paging->hasEntries());
    }

    public function testSighupDoesNotShutdownTheServer(): void
    {
        if (!extension_loaded('posix')) {
            $this->markTestSkipped('The posix extension is required to send signals.');
        }

        $this->authenticateUser();
        $this->assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );

        $this->sendServerSignal(SIGHUP);

        // Give the async signal handler a moment to run before checking state.
        usleep(250_000);

        $this->assertTrue(
            $this->isServerRunning(),
            'The server must remain running after SIGHUP.',
        );

        $newClient = $this->buildClient('tcp');

        try {
            $newClient->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
            $this->assertSame(
                'dn:cn=user,dc=foo,dc=bar',
                $newClient->whoami(),
            );
        } finally {
            try {
                $newClient->unbind();
            } catch (Throwable) {
                // Connection may already be closed; ignore unbind failures.
            }
        }
    }

    private function personEntry(string $cn): Entry
    {
        return Entry::fromArray("cn={$cn},dc=foo,dc=bar", [
            'objectClass' => ['inetOrgPerson'],
            'cn' => [$cn],
            'sn' => ['Test'],
        ]);
    }
}
