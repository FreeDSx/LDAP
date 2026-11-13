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

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use RuntimeException;

/**
 * A client that sends a request a byte at a time onto the test server.
 */
trait DripsRequestsTrait
{
    /**
     * The bytes of the request sent at once before the drip starts.
     */
    private const DRIP_FIRST_BYTES = 10;

    private const DRIP_INTERVAL_MICROSECONDS = 250_000;

    /**
     * Sends the start of a request, then a byte at a time until the server closes the connection.
     *
     * @return float|null the seconds from the first bytes to the close, or null when the server never closed it.
     */
    private function dripRequestUntilClosed(
        string $transport,
        float $giveUpAfter,
    ): ?float {
        $client = self::openDripClient($transport);
        $request = (new LdapEncoder())->encode((new LdapMessageRequest(
            1,
            Operations::search(Filters::equal(
                'cn',
                str_repeat(
                    'x',
                    200,
                ),
            ))->base('dc=foo,dc=bar'),
        ))->toAsn1());

        try {
            fwrite(
                $client,
                substr(
                    $request,
                    0,
                    self::DRIP_FIRST_BYTES,
                ),
            );
            $startedAt = microtime(true);
            $offset = self::DRIP_FIRST_BYTES;
            while (microtime(true) - $startedAt < $giveUpAfter && $offset < strlen($request)) {
                if (self::hasClosed($client)) {
                    return microtime(true) - $startedAt;
                }
                @fwrite(
                    $client,
                    $request[$offset++],
                );
            }

            return null;
        } finally {
            fclose($client);
        }
    }

    /**
     * @return resource
     */
    private static function openDripClient(string $transport)
    {
        $client = stream_socket_client(
            ($transport === 'ssl' ? 'tls' : 'tcp') . '://127.0.0.1:' . TestWorker::port(),
            $errorNumber,
            $errorMessage,
            5.0,
            STREAM_CLIENT_CONNECT,
            stream_context_create([
                'ssl' => [
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                ],
            ]),
        );
        if ($client === false) {
            throw new RuntimeException('Unable to connect: ' . $errorMessage);
        }
        // A TLS session ticket can leave the stream readable with no data behind it.
        stream_set_blocking(
            $client,
            false,
        );

        return $client;
    }

    /**
     * Waits one drip interval for the server to close the connection.
     *
     * @param resource $client
     */
    private static function hasClosed($client): bool
    {
        $read = [$client];
        $write = [];
        $except = [];
        $ready = @stream_select(
            $read,
            $write,
            $except,
            0,
            self::DRIP_INTERVAL_MICROSECONDS,
        );
        if ($ready !== 1) {
            return false;
        }
        $data = fread(
            $client,
            8192,
        );

        return ($data === '' || $data === false) && feof($client);
    }
}
