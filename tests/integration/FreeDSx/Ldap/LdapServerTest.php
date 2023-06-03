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

namespace integration\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

class LdapServerTest extends ServerTestCase
{
    public function setUp(): void
    {
        $this->setServerMode('ldapserver');

        parent::setUp();

        $this->createServerProcess('tcp');
    }

    public function testItCanBind(): void
    {
        $response = $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345'
        );
        $output = $this->waitForServerOutput('---bind---');

        $this->assertNotNull($response);
        $this->assertStringContainsString(
            'username => cn=user,dc=foo,dc=bar',
            $output
        );
        $this->assertStringContainsString(
            'password => 12345',
            $output
        );
    }

    public function testItRejectsBindWithIncorrectCredentials(): void
    {
        $bindException = null;

        try {
            $this->ldapClient()->bind(
                'cn=fake,dc=foo,dc=bar',
                'also-fake'
            );
        } catch (BindException $exception) {
            $bindException = $exception;
        }

        $this->assertNotNull($bindException);
    }

    public function testItPerformsAnAdd(): void
    {
        $this->authenticate();
        $response = $this->ldapClient()->create(Entry::fromArray(
            'cn=meh,dc=foo,dc=bar',
            [
                'foo' => 'bar',
            ]
        ));
        $output = $this->waitForServerOutput('---add---');

        $this->assertNotNull($response);
        $this->assertStringContainsString(
            'dn => cn=meh,dc=foo,dc=bar',
            $output
        );
        $this->assertStringContainsString(
            'Attributes: foo => bar',
            $output
        );
    }

    public function testItPerformsDelete(): void
    {
        $this->authenticate();
        $response = $this->ldapClient()->delete('cn=meh,dc=foo,dc=bar');
        $output = $this->waitForServerOutput('---delete---');

        $this->assertNotNull($response);
        $this->assertStringContainsString(
            'dn => cn=meh,dc=foo,dc=bar',
            $output
        );
    }

    public function testItPerformsModify(): void
    {
        $this->authenticate();

        $entry = Entry::fromArray(
            'cn=meh,dc=foo,dc=bar',
            [
                'phone' => '123-456-7890',
                'email' => 'meh@bleh.local',
                'surname' => 'oh',
                'givenName' => 'fake',
            ]
        );
        $entry->add('email', 'foo@bar.local');
        $entry->remove('givenName', 'FirstName');
        $entry->set('surname', 'LastName');
        $entry->reset('phone');

        $response = $this->ldapClient()->update($entry);
        $output = $this->waitForServerOutput('---modify---');

        $this->assertNotNull($response);
        $this->assertStringContainsString(
            'dn => cn=meh,dc=foo,dc=bar',
            $output
        );
        $this->assertStringContainsString(
            'Changes: (0)email => foo@bar.local, (1)givenName => FirstName, (2)surname => LastName, (1)phone => ',
            $output
        );
    }

    public function testItPerformsSearches(): void
    {
        $this->authenticate();

        $response = $this->ldapClient()->read('cn=meh,dc=foo,dc=bar');
        $output = $this->waitForServerOutput('---search---');

        $this->assertNotNull($response);
        $this->assertStringContainsString(
            'dn => cn=meh,dc=foo,dc=bar',
            $output
        );
        $this->assertStringContainsString(
            'filter => (objectClass=*)',
            $output
        );
    }

    public function testItCanPerformCompare(): void
    {
        $this->authenticate();

        $response = $this->ldapClient()->compare(
            'cn=meh,dc=foo,dc=bar',
            'foo',
            'bar'
        );
        $output = $this->waitForServerOutput('---compare---');

        $this->assertNotNull($response);
        $this->assertStringContainsString(
            'dn => cn=meh,dc=foo,dc=bar',
            $output
        );
        $this->assertStringContainsString(
            'Name => foo',
            $output
        );
        $this->assertStringContainsString(
            'Value => bar',
            $output
        );
    }

    public function testItCanModifyDn(): void
    {
        $this->authenticate();

        $response = $this->ldapClient()->move(
            'cn=meh,dc=foo,dc=bar',
            'cn=bleh,dc=foo,dc=bar'
        );
        $output = $this->waitForServerOutput('---modify-dn---');

        $this->assertNotNull($response);
        $this->assertStringContainsString(
            'dn => cn=meh,dc=foo,dc=bar',
            $output
        );
        $this->assertStringContainsString(
            'ParentDn => cn=bleh,dc=foo,dc=bar',
            $output
        );
        $this->assertStringContainsString(
            'ParentRdn => cn=meh',
            $output
        );
    }

    public function testItCanRetrieveTheRootDSE(): void
    {
        $rootDse = $this->ldapClient()->read();

        $this->assertNotNull($rootDse);
        $this->assertEquals(
            [
                'namingContexts' => [
                    'dc=FreeDSx,dc=local',
                ],
                'supportedExtension' => [
                    '1.3.6.1.4.1.4203.1.11.3',
                    '1.3.6.1.4.1.1466.20037',
                ],
                'supportedLDAPVersion' => [
                    '3',
                ],
                'vendorName' => [
                    'FreeDSx',
                ],
            ],
            $rootDse->toArray()
        );
    }

    public function testThatOperationCompareRequireAuthentication(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->compare('dc=foo,dc=bar', 'foo', 'bar');
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

        $this->ldapClient()->create(Entry::fromArray('dc=foo,dc=bar', ['foo' => 'bar']));
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

        $this->ldapClient()->move('dc=foo,dc=bar', 'cn=here, dc=foo, dc=bar');
    }

    public function testWhoAmIWhenAuthenticated(): void
    {
        $this->authenticate();
        $output = $this->ldapClient()->whoami();

        $this->assertEquals('dn:cn=user,dc=foo,dc=bar', $output);
    }

    public function testWhoAmIWhenNotAuthenticated(): void
    {
        $output = $this->ldapClient()->whoami();

        $this->assertNull($output);
    }

    public function testItCanHandlingPaging(): void
    {
        $this->stopServer();
        $this->createServerProcess('tcp', 'paging');
        $this->authenticate();

        $allEntries = [];
        $i = 0;

        $search = Operations::search(Filters::raw('(cn=foo)'));
        $paging = $this->ldapClient()->paging($search);

        while ($paging->hasEntries()) {
            $i++;
            $entries = $paging->getEntries(100);
            $allEntries = array_merge(
                $allEntries,
                $entries->toArray()
            );

            $output = $this->waitForServerOutput('---paging---');

            if ($i === 3) {
                $this->assertStringContainsString('Final response', $output);
            } else {
                $this->assertStringContainsString('Regular response', $output);
            }
        }

        $this->assertCount(300, $allEntries);
    }

    public function testItThrowsAnExceptionForPagingWhenNotSupported(): void
    {
        $this->authenticate();

        $this->expectExceptionMessage('The server does not support the paging control.');
        $this->expectExceptionCode(ResultCode::UNAVAILABLE_CRITICAL_EXTENSION);

        $search = Operations::search(Filters::raw('(cn=foo)'));
        $this->ldapClient()->paging($search)
            ->isCritical()
            ->getEntries();
    }

    public function testItDoesASearchWhenPagingIsNotMarkedAsCritical(): void
    {
        $this->authenticate();

        $search = Operations::search(Filters::raw('(cn=foo)'));
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

    public function testItCanRunOverUnixSocket(): void
    {
        $this->stopServer();
        $this->createServerProcess('unix');

        $result = $this->ldapClient()->read('');
        $this->assertNotNull($result);
    }

    public function testItCanHandleMultipleClients(): void
    {
        $this->ldapClient()->read();
        $client2 = $this->getClient($this->ldapClient()->getOptions());

        $result = $client2->read();
        $this->assertNotNull($result);
    }
}
