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

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operations;

final class LdapServerReloadTest extends ServerTestCase
{
    private string $reloadFlagFile;

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        $this->reloadFlagFile = sys_get_temp_dir() . '/ldap_reload_flag_' . getmypid() . '.txt';
        @unlink($this->reloadFlagFile);

        parent::setUp();

        $this->createServerProcess(
            'tcp',
            ['--reload-flag-file=' . $this->reloadFlagFile],
        );
    }

    public function tearDown(): void
    {
        @unlink($this->reloadFlagFile);

        parent::tearDown();
    }

    public function testSighupReloadEnablesAnonymousBindForNewConnections(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->send(Operations::bindAnonymously());
    }

    public function testSighupReloadAppliesTheFileDrivenConfiguration(): void
    {
        file_put_contents(
            $this->reloadFlagFile,
            'allow-anonymous',
        );

        $this->sendServerSignal(SIGHUP);
        $this->waitForServerOutput('configuration reloaded...');

        $client = $this->buildClient('tcp');
        $response = $client
            ->send(Operations::bindAnonymously())
            ?->getResponse();
        $client->unbind();

        $this->assertInstanceOf(
            BindResponse::class,
            $response,
        );
        $this->assertSame(
            0,
            $response->getResultCode(),
        );
    }

    public function testSighupReloadRefusesAConfigurationTheServerWouldRefuseToStartWith(): void
    {
        file_put_contents(
            $this->reloadFlagFile,
            'unstartable',
        );

        $this->sendServerSignal(SIGHUP);
        $this->waitForServerOutput('configuration reloaded...');

        $this->expectException(BindException::class);

        $this->buildClient('tcp')->send(Operations::bindAnonymously());
    }
}
