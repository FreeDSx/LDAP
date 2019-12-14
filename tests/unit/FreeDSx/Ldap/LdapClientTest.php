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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Response\AddResponse;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

class LdapClientTest extends LdapTestCase
{
    /**
     * @var LdapClient
     */
    protected $client;

    public function setUp(): void
    {
        $this->client = $this->getClient();
    }

    public function tearDown(): void
    {
        try {
            @$this->client->unbind();
        } catch (\Exception|\Throwable $exception) {
        }
    }

    public function testUsernamePasswordBind()
    {
        $response = $this->client->bind($_ENV['LDAP_USERNAME'], $_ENV['LDAP_PASSWORD'])->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testAnonymousBind()
    {
        $response = $this->client->send(Operations::bindAnonymously())->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testSaslBindWithAutoSelectingTheMechanism()
    {
        $response = $this->client->bindSasl($this->getSaslOptions());
        $response = $response->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testSaslBindWithCramMD5()
    {
        if ($this->isActiveDirectory()) {
            $this->markTestSkipped('CRAM-MD5 not supported on AD.');
        }
        $response = $this->client->bindSasl(
            $this->getSaslOptions(),
            'CRAM-MD5'
        );
        $response = $response->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testSaslBindWithDigestMD5()
    {
        $response = $this->client->bindSasl(
            $this->getSaslOptions(),
            'DIGEST-MD5'
        );
        $response = $response->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testSaslBindWithAnIntegritySecurityLayerIsFunctional()
    {
        $this->client->bindSasl(
            array_merge($this->getSaslOptions(),['use_integrity' => true]),
            'DIGEST-MD5'
        );
        $entry = $this->client->read('', ['supportedSaslMechanisms']);

        $this->assertInstanceOf(Entry::class, $entry);
    }

    public function testCompareOperation()
    {
        $this->bindClient($this->client);

        $success = $this->client->compare('cn=Birgit Pankhurst,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com', 'cn', 'Birgit Pankhurst');
        $failure = $this->client->compare('cn=Birgit Pankhurst,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com', 'cn', 'foo');

        $this->assertTrue($success);
        $this->assertFalse($failure);
    }

    public function testCreateOperation()
    {
        $this->bindClient($this->client);

        $attributes = [
            'objectClass' => ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
            'cn' => ['Foo'],
            'sn' => ['Bar'],
            'description' => ['FreeDSx Unit Test'],
            'uid' => ['Foo'],
            'givenName' => ['Foo'],
        ];

        $response = $this->client->create(Entry::fromArray('cn=Foo,ou=FreeDSx-Test,dc=example,dc=com', $attributes))->getResponse();
        $this->assertInstanceOf(AddResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());

        # Testing across AD / OpenLDAP. Ignore the ObjectClass differences...
        unset($attributes['objectClass']);

        $entry = $this->client->read('cn=Foo,ou=FreeDSx-Test,dc=example,dc=com', array_keys($attributes));
        $this->assertEquals($attributes, $entry->toArray());
    }

    public function testReadOperation()
    {
        $this->bindClient($this->client);

        $attributes = [
            'cn' => ['Carmelina Esposito'],
            'sn' => ['Esposito'],
            'description' =>  ["This is Carmelina Esposito's description"],
            'facsimileTelephoneNumber' => ['+1 415 116-9439'],
            'l' => ['San Jose'],
            'postalAddress' => ['Product Testing$San Jose'],
        ];
        $entry = $this->client->read('cn=Carmelina Esposito,ou=Product Testing,ou=FreeDSx-Test,dc=example,dc=com', array_keys($attributes));

        $this->assertInstanceOf(Entry::class, $entry);
        $this->assertEquals(strtolower($entry->getDn()->toString()),strtolower('cn=Carmelina Esposito,ou=Product Testing,ou=FreeDSx-Test,dc=example,dc=com'));
        $this->assertEquals($entry->toArray(), $attributes);
    }

    public function testDeleteOperation()
    {
        $this->bindClient($this->client);

        $response = $this->client->delete('cn=Foo,ou=FreeDSx-Test,dc=example,dc=com')->getResponse();
        $this->assertInstanceOf(DeleteResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testModifyOperation()
    {
        $this->bindClient($this->client);

        $entry = new Entry('cn=Kathrine Erbach,ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com');
        $entry->reset('facsimileTelephoneNumber');
        $entry->remove('mobile', '+1 510 957-7341');
        $entry->add('mobile', '+1 555 555-5555');
        $entry->remove('homePhone', '+1 510 991-4348');
        $entry->set('title', 'Head Payroll Dude');

        $response = $this->client->update($entry)->getResponse();
        $this->assertInstanceOf(ModifyResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
        $this->assertEmpty($entry->changes()->toArray());

        $modified = $this->client->read('cn=Kathrine Erbach,ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com', [
            'facsimileTelephoneNumber',
            'mobile',
            'homePhone',
            'title',
        ]);
        $this->assertEquals(['mobile' => ['+1 555 555-5555'], 'title' => ['Head Payroll Dude']], $modified->toArray());
    }

    public function testRenameOperation()
    {
        $this->bindClient($this->client);

        $result = $this->client->rename('cn=Arleen Sevigny,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com', 'cn=Arleen Sevigny-Foo');
        $entry = $this->client->read('cn=Arleen Sevigny-Foo,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com', ['cn']);

        $this->assertInstanceOf(ModifyDnResponse::class, $result->getResponse());
        $this->assertInstanceOf(Entry::class, $entry);
        $this->assertEquals(['Arleen Sevigny-Foo'], $entry->get('cn')->getValues());
    }

    public function testRenameWithoutDeleteOperation()
    {
        if ($this->isActiveDirectory()) {
            $this->markTestSkipped('Rename without delete not supported in Active Directory.');
        }
        $this->bindClient($this->client);

        $result = $this->client->rename('cn=Farouk Langdon,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com', 'cn=Farouk Langdon-Bar', false);
        $entry = $this->client->read('cn=Farouk Langdon-Bar,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com', ['cn']);

        $this->assertInstanceOf(ModifyDnResponse::class, $result->getResponse());
        $this->assertInstanceOf(Entry::class, $entry);
        $this->assertContains('Farouk Langdon', $entry->get('cn')->getValues());
        $this->assertContains('Farouk Langdon-Bar', $entry->get('cn')->getValues());
    }

    public function testMoveOperation()
    {
        $this->markTestSkipped('Rename without delete not supported in Active Directory.');
        $this->bindClient($this->client);

        $result = $this->client->move('cn=Minne Schmelzel,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com', 'ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com');
        $entry = $this->client->read('cn=Minne Schmelzel,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertInstanceOf(ModifyDnResponse::class, $result->getResponse());
        $this->assertInstanceOf(Entry::class, $entry);
    }

    public function testSubSearchOperation()
    {
        $this->bindClient($this->client);

        $entries = $this->client->search(Operations::search(Filters::raw('(&(objectClass=inetOrgPerson)(cn=A*))')));
        $this->assertInstanceOf(Entries::class, $entries);
        $this->assertEquals(843, $entries->count());
    }

    public function testListSearchOperation()
    {
        $this->bindClient($this->client);

        $entries = $this->client->search(Operations::list(Filters::raw('(&(objectClass=inetOrgPerson)(cn=A*))'), 'ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com'));
        $this->assertInstanceOf(Entries::class, $entries);
        $this->assertEquals(100, $entries->count());

        /** @var Entry $entry */
        foreach ($entries as $entry) {
            $this->assertEquals(strtolower('ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com'),strtolower($entry->getDn()->getParent()->toString()));
        }
    }

    public function testWhoAmI()
    {
        $this->bindClient($this->client);

        $this->assertRegExp('/^(dn|u):.*/', $this->client->whoami());
    }

    public function testStartTls()
    {
        $this->client = $this->getClient();
        $this->client->startTls();

        $this->assertTrue(true);
    }

    public function testStartTlsFailure()
    {
        $this->client = $this->getClient(['servers' => 'foo.com']);

        $this->expectException(ConnectionException::class);
        @$this->client->startTls();
    }

    public function testStartTlsIgnoreCertValidation()
    {
        $this->client = $this->getClient(['servers' => 'foo.com', 'ssl_validate_cert' => false]);

        $this->client->startTls();
        $this->assertTrue(true);
    }

    public function testUseSsl()
    {
        $this->client = $this->getClient(['use_ssl' => true, 'port' => 636]);
        $this->client->read('');

        $this->assertTrue(true);
    }

    public function testUseSslFailure()
    {
        $this->client = $this->getClient(['servers' => 'foo.com', 'use_ssl' => true, 'port' => 636]);

        $this->expectException(ConnectionException::class);
        $this->client->read('');
    }

    public function testUseSslIgnoreCertValidation()
    {
        $this->client = $this->getClient([
            'servers' => 'foo.com',
            'ssl_validate_cert' => false,
            'use_ssl' => true,
            'port' => 636,
        ]);

        $this->client->read('');
        $this->assertTrue(true);
    }

    protected function getSaslOptions(): array
    {
        if ($this->isActiveDirectory()) {
            return [
                'username' => 'admin',
                'password' =>  $_ENV['LDAP_PASSWORD'],
                'host' => 'ADDC3.example.com'
            ];
        } else {
            return [
                'username' => 'WillifoA',
                'password' => 'Password1',
            ];
        }
    }
}
