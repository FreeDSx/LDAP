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

use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

use function file_put_contents;
use function unlink;

/**
 * Runs the shared runner suite against the PcntlServerRunner.
 */
final class ServerRunnerPcntlTest extends ServerRunnerTestCase
{
    use RawClientQueueTrait;

    public function testASessionThatCannotFollowAReloadIsEndedAsUnavailable(): void
    {
        $this->requirePosix();
        $flagFile = $this->makeFlagFile();
        $this->createServerProcess(
            'tcp',
            ['--log', '--reload-flag-file=' . $flagFile],
        );
        $queue = $this->rawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            1,
            new SimpleBindRequest(
                'cn=user,dc=foo,dc=bar',
                '12345',
            ),
        ));
        $queue->getMessage(1);

        try {
            file_put_contents(
                $flagFile,
                'deny-sn-parent-only',
            );
            $this->sendServerSignal(SIGHUP);

            $queue->getMessage();
            self::fail('The session continued under the access policy the server moved on from.');
        } catch (UnsolicitedNotificationException $e) {
            self::assertTrue($e->isNoticeOfDisconnection());
            self::assertSame(
                ResultCode::UNAVAILABLE,
                $e->getCode(),
            );
        } finally {
            $queue->close();
            @unlink($flagFile);
        }
    }

    /**
     * The parent reloads first, then each connection child applies it for itself.
     */
    protected function reloadServer(): void
    {
        $this->sendServerSignal(SIGHUP);
        $this->waitForServerOutput('A client connection applied the reloaded configuration.');
    }
}
