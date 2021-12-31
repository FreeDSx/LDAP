<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace unit\FreeDSx\Ldap;

use Exception;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\ResultCode;
use Symfony\Component\Process\Process;

class LdapServerTest extends LdapTestCase
{
    /**
     * @var Process
     */
    private $subject;

    /**
     * @var LdapClient
     */
    private $client;

    public function setUp(): void
    {
        parent::setUp();

        $this->subject = new Process([
            'php',
            __DIR__ . '/../../../bin/ldapserver.php'
        ]);
        $this->subject->start();
        $this->waitForServerOutput('server starting...');

        $this->client = new LdapClient([
            'port' => 3389,
            'servers' => '127.0.0.1',
            'ssl_validate_cert' => false,
        ]);
    }

    public function tearDown(): void
    {
        parent::tearDown();
        $this->client->unbind();
        $this->client = null;
        $this->subject->stop();
    }

    public function testItAcceptsBindWithCorrectCredentials(): void
    {
        $response = $this->client->bind(
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
            $this->client->bind(
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
        $response = $this->client->create(Entry::fromArray(
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
        $response = $this->client->delete('cn=meh,dc=foo,dc=bar');
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

        $response = $this->client->update($entry);
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

        $response = $this->client->read('cn=meh,dc=foo,dc=bar');
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

        $response = $this->client->compare(
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

        $response = $this->client->move(
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

    public function testItCanRetrieveTheRootDSE()
    {
        $rootDse = $this->client->read();

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

    public function testThatOperationCompareRequireAuthentication()
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->client->compare('dc=foo,dc=bar', 'foo', 'bar');
    }

    public function testThatOperationSearchRequireAuthentication()
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->client->read('dc=foo,dc=bar');
    }

    public function testThatOperationAddRequireAuthentication()
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->client->create(Entry::fromArray('dc=foo,dc=bar', ['foo' => 'bar']));
    }

    public function testThatOperationDeleteRequireAuthentication()
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->client->delete('dc=foo,dc=bar');
    }

    public function testThatOperationModifyRequireAuthentication()
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $entry = Entry::fromArray('cn=foo,dc=foo,dc=bar');
        $entry->add('email', 'foo@bar.local');

        $this->client->update($entry);
    }

    public function testThatOperationModifyDnRequireAuthentication()
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->client->move('dc=foo,dc=bar', 'cn=here, dc=foo, dc=bar');
    }

    public function testWhoAmIWhenAuthenticated()
    {
        $this->authenticate();
        $output = $this->client->whoami();

        $this->assertEquals('dn:cn=user,dc=foo,dc=bar', $output);
    }

    public function testWhoAmIWhenNotAuthenticated()
    {
        $output = $this->client->whoami();

        $this->assertNull($output);
    }

    public function testItCanStartTLSThenStillPerformOperations()
    {
        $this->client->startTls();
        $result = $this->client->read();

        $this->assertNotNull($result);
    }

    private function authenticate(): void
    {
        $this->client->bind(
            'cn=user,dc=foo,dc=bar',
            '12345'
        );
    }

    private function waitForServerOutput(string $marker): string
    {
        $maxWait = 10;
        $i = 0;

        while ($this->subject->isRunning()) {
            $output = $this->subject->getOutput();
            //$this->subject->clearOutput();

            if (strpos($output, $marker) !== false) {
                return $output;
            }

            $i++;
            if ($i === $maxWait) {
                break;
            }

            sleep(1);
        }

        throw new Exception(sprintf(
            'The expected output (%s) was not received after %d seconds.',
            $marker,
            $i
        ));
    }
}
