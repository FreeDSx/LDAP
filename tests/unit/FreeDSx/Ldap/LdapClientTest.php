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
    protected static $client;

    public static function setUpBeforeClass()
    {
        self::$client = self::getClient();
    }

    public static function tearDownAfterClass()
    {
        try {
            @self::$client->unbind();
        } catch (\Exception|\Throwable $exception) {
        }
    }

    public function testUsernamePasswordBind()
    {
        $response = self::$client->bind($_ENV['LDAP_USERNAME'], $_ENV['LDAP_PASSWORD'])->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testAnonymousBind()
    {
        $response = self::$client->send(Operations::bindAnonymously())->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testSaslBindWithAutoSelectingTheMechanism()
    {
        $response = self::$client->bindSasl($this->getSaslOptions());
        $response = $response->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testSaslBindWithCramMD5()
    {
        if ($this->isActiveDirectory()) {
            $this->markTestSkipped('CRAM-MD5 not supported on AD.');
        }
        $response = self::$client->bindSasl(
            $this->getSaslOptions(),
            'CRAM-MD5'
        );
        $response = $response->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testSaslBindWithDigestMD5()
    {
        $response = self::$client->bindSasl(
            $this->getSaslOptions(),
            'DIGEST-MD5'
        );
        $response = $response->getResponse();

        $this->assertInstanceOf(BindResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testSaslBindWithAnIntegritySecurityLayerIsFunctional()
    {
        self::$client->bindSasl(
            array_merge($this->getSaslOptions(),['use_integrity' => true]),
            'DIGEST-MD5'
        );
        $entry = self::$client->read('', ['supportedSaslMechanisms']);

        $this->assertInstanceOf(Entry::class, $entry);
    }

    public function testCompareOperation()
    {
        self::bindClient(self::$client);

        $success = self::$client->compare('cn=Birgit Pankhurst,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com', 'cn', 'Birgit Pankhurst');
        $failure = self::$client->compare('cn=Birgit Pankhurst,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com', 'cn', 'foo');

        $this->assertTrue($success);
        $this->assertFalse($failure);
    }

    public function testCreateOperation()
    {
        self::bindClient(self::$client);

        $attributes = [
            'objectClass' => ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
            'cn' => ['Foo'],
            'sn' => ['Bar'],
            'description' => ['FreeDSx Unit Test'],
            'uid' => ['Foo'],
            'givenName' => ['Foo'],
        ];

        $response = self::$client->create(Entry::fromArray('cn=Foo,ou=FreeDSx-Test,dc=example,dc=com', $attributes))->getResponse();
        $this->assertInstanceOf(AddResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());

        # Testing across AD / OpenLDAP. Ignore the ObjectClass differences...
        unset($attributes['objectClass']);

        $entry = self::$client->read('cn=Foo,ou=FreeDSx-Test,dc=example,dc=com', array_keys($attributes));
        $this->assertEquals($attributes, $entry->toArray());
    }

    public function testReadOperation()
    {
        self::bindClient(self::$client);

        $attributes = [
            'cn' => ['Carmelina Esposito'],
            'sn' => ['Esposito'],
            'description' =>  ["This is Carmelina Esposito's description"],
            'facsimileTelephoneNumber' => ['+1 415 116-9439'],
            'l' => ['San Jose'],
            'postalAddress' => ['Product Testing$San Jose'],
        ];
        $entry = self::$client->read('cn=Carmelina Esposito,ou=Product Testing,ou=FreeDSx-Test,dc=example,dc=com', array_keys($attributes));

        $this->assertInstanceOf(Entry::class, $entry);
        $this->assertEquals(strtolower($entry->getDn()->toString()),strtolower('cn=Carmelina Esposito,ou=Product Testing,ou=FreeDSx-Test,dc=example,dc=com'));
        $this->assertEquals($entry->toArray(), $attributes);
    }

    public function testDeleteOperation()
    {
        self::bindClient(self::$client);

        $response = self::$client->delete('cn=Foo,ou=FreeDSx-Test,dc=example,dc=com')->getResponse();
        $this->assertInstanceOf(DeleteResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
    }

    public function testModifyOperation()
    {
        self::bindClient(self::$client);

        $entry = new Entry('cn=Kathrine Erbach,ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com');
        $entry->reset('facsimileTelephoneNumber');
        $entry->remove('mobile', '+1 510 957-7341');
        $entry->add('mobile', '+1 555 555-5555');
        $entry->remove('homePhone', '+1 510 991-4348');
        $entry->set('title', 'Head Payroll Dude');

        $response = self::$client->update($entry)->getResponse();
        $this->assertInstanceOf(ModifyResponse::class, $response);
        $this->assertEquals(0, $response->getResultCode());
        $this->assertEmpty($entry->changes()->toArray());

        $modified = self::$client->read('cn=Kathrine Erbach,ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com', [
            'facsimileTelephoneNumber',
            'mobile',
            'homePhone',
            'title',
        ]);
        $this->assertEquals(['mobile' => ['+1 555 555-5555'], 'title' => ['Head Payroll Dude']], $modified->toArray());
    }

    public function testRenameOperation()
    {
        self::bindClient(self::$client);

        $result = self::$client->rename('cn=Arleen Sevigny,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com', 'cn=Arleen Sevigny-Foo');
        $entry = self::$client->read('cn=Arleen Sevigny-Foo,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com', ['cn']);

        $this->assertInstanceOf(ModifyDnResponse::class, $result->getResponse());
        $this->assertInstanceOf(Entry::class, $entry);
        $this->assertEquals(['Arleen Sevigny-Foo'], $entry->get('cn')->getValues());
    }

    public function testRenameWithoutDeleteOperation()
    {
        if (self::isActiveDirectory()) {
            $this->markTestSkipped('Rename without delete not supported in Active Directory.');
        }
        self::bindClient(self::$client);

        $result = self::$client->rename('cn=Farouk Langdon,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com', 'cn=Farouk Langdon-Bar', false);
        $entry = self::$client->read('cn=Farouk Langdon-Bar,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com', ['cn']);

        $this->assertInstanceOf(ModifyDnResponse::class, $result->getResponse());
        $this->assertInstanceOf(Entry::class, $entry);
        $this->assertContains('Farouk Langdon', $entry->get('cn')->getValues());
        $this->assertContains('Farouk Langdon-Bar', $entry->get('cn')->getValues());
    }

    public function testMoveOperation()
    {
        self::bindClient(self::$client);

        $result = self::$client->move('cn=Minne Schmelzel,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com', 'ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com');
        $entry = self::$client->read('cn=Minne Schmelzel,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertInstanceOf(ModifyDnResponse::class, $result->getResponse());
        $this->assertInstanceOf(Entry::class, $entry);
    }

    public function testSubSearchOperation()
    {
        self::bindClient(self::$client);

        $entries = self::$client->search(Operations::search(Filters::raw('(&(objectClass=inetOrgPerson)(cn=A*))')));
        $this->assertInstanceOf(Entries::class, $entries);
        $this->assertEquals(843, $entries->count());
    }

    public function testListSearchOperation()
    {
        self::bindClient(self::$client);

        $entries = self::$client->search(Operations::list(Filters::raw('(&(objectClass=inetOrgPerson)(cn=A*))'), 'ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com'));
        $this->assertInstanceOf(Entries::class, $entries);
        $this->assertEquals(100, $entries->count());

        /** @var Entry $entry */
        foreach ($entries as $entry) {
            $this->assertEquals(strtolower('ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com'),strtolower($entry->getDn()->getParent()->toString()));
        }
    }

    public function testWhoAmI()
    {
        self::bindClient(self::$client);

        $this->assertRegExp('/^(dn|u):.*/', self::$client->whoami());
    }

    public function testStartTls()
    {
        self::$client = self::getClient();
        self::$client->startTls();

        $this->assertTrue(true);
    }

    public function testStartTlsFailure()
    {
        self::$client = self::getClient(['servers' => 'foo.com']);

        $this->expectException(ConnectionException::class);
        @self::$client->startTls();
    }

    public function testStartTlsIgnoreCertValidation()
    {
        self::$client = self::getClient(['servers' => 'foo.com', 'ssl_validate_cert' => false]);

        self::$client->startTls();
        $this->assertTrue(true);
    }

    public function testUseSsl()
    {
        self::$client = self::getClient(['use_ssl' => true, 'port' => 636]);
        self::$client->read('');

        $this->assertTrue(true);
    }

    public function testUseSslFailure()
    {
        self::$client = self::getClient(['servers' => 'foo.com', 'use_ssl' => true, 'port' => 636]);

        $this->expectException(ConnectionException::class);
        self::$client->read('');
    }

    public function testUseSslIgnoreCertValidation()
    {
        self::$client = self::getClient([
            'servers' => 'foo.com',
            'ssl_validate_cert' => false,
            'use_ssl' => true,
            'port' => 636,
        ]);

        self::$client->read('');
        $this->assertTrue(true);
    }

    protected function getSaslOptions(): array
    {
        if ($this->isActiveDirectory()) {
            return [
                'username' => 'admin',
                'password' =>  $_ENV['LDAP_PASSWORD'],
                'host' => gethostname()
            ];
        } else {
            return [
                'username' => 'WillifoA',
                'password' => 'Password1',
            ];
        }
    }
}
