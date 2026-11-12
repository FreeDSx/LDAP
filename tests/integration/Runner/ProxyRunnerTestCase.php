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

namespace Tests\Integration\FreeDSx\Ldap\Runner;

use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

use function extension_loaded;

/**
 * Proxy behavior that runs against every server runner.
 */
abstract class ProxyRunnerTestCase extends ServerTestCase
{
    use RawClientQueueTrait;

    public static function setUpBeforeClass(): void
    {
        if (!static::isRunnerAvailable()) {
            return;
        }
        parent::setUpBeforeClass();

        static::initSharedServer(
            'ldap-proxy',
            'tcp',
            static::runnerArgs(),
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-proxy');

        parent::setUp();
    }

    public function testItForwardsABoundSearchToTheUpstream(): void
    {
        $this->authenticateUser();

        self::assertCount(
            12,
            $this->ldapClient()->search(
                Operations::search(Filters::equal('sn', 'Entry'))->base('dc=foo,dc=bar'),
            ),
        );
    }

    public function testAClientThatStopsReadingIsClosedAsAWriteTimeoutAndOthersAreStillServed(): void
    {
        $this->createServerProcess(
            'tcp',
            [
                '--log',
                '--write-timeout=2',
                '--entries=300',
                '--entry-padding=65536',
            ],
        );

        $stalled = $this->boundRawQueue();
        $stalled->sendMessage(new LdapMessageRequest(
            2,
            Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar'),
        ));

        try {
            $this->waitForServerOutput('The connection was closed because the client stopped reading.');
        } finally {
            $stalled->close();
        }

        $this->authenticateUser();
        self::assertNotNull($this->ldapClient()->read('dc=foo,dc=bar'));
    }

    /**
     * Appends the runner selection to every proxy this suite starts, including the per-test ones.
     *
     * @param list<string> $extraArgs
     */
    protected function createServerProcess(
        string $transport,
        array $extraArgs = [],
        ?int $openFileLimit = null,
    ): void {
        parent::createServerProcess(
            $transport,
            [...$extraArgs, ...static::runnerArgs()],
            $openFileLimit,
        );
    }

    /**
     * Hook for subclasses to name the runner the proxy runs under.
     *
     * @return list<string>
     */
    protected static function runnerArgs(): array
    {
        return [];
    }

    /**
     * Whether this runner can run here, which the pcntl one cannot without process control.
     */
    protected static function isRunnerAvailable(): bool
    {
        return extension_loaded('pcntl')
            && extension_loaded('posix');
    }
}
