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
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

use function extension_loaded;

/**
 * Proxy behavior that runs against every server runner.
 */
abstract class ProxyRunnerTestCase extends ServerTestCase
{
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
