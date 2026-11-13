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

use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Decoder\ResponseMessageDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use RuntimeException;

use function array_map;
use function feof;
use function fread;
use function fwrite;
use function microtime;
use function range;
use function str_repeat;
use function stream_set_timeout;
use function stream_socket_client;
use function substr;
use function usleep;

/**
 * Requests that hold the request budget of the test server.
 */
trait RequestBudgetClientTrait
{
    /**
     * How long to wait for a response to arrive on a client opened here.
     */
    private const RESPONSE_WAIT_SECONDS = 10;

    /**
     * Sends most of a request it never finishes, leaving the server holding what the request declared.
     *
     * @return resource
     */
    private function stalledClient(int $bytes)
    {
        $client = $this->openClient();
        $request = self::encodedRequest(new LdapMessageRequest(
            1,
            Operations::modify(
                'cn=user,dc=foo,dc=bar',
                Change::replace(
                    'description',
                    str_repeat(
                        'x',
                        $bytes + 10_000,
                    ),
                ),
            ),
        ));
        fwrite(
            $client,
            substr(
                $request,
                0,
                $bytes,
            ),
        );
        // Gives the server time to buffer the bytes before anything else arrives.
        usleep(1_000_000);

        return $client;
    }

    /**
     * A connection that requests are written to a part at a time.
     *
     * @return resource
     */
    private function openClient()
    {
        $client = stream_socket_client(
            'tcp://127.0.0.1:' . TestWorker::port(),
            $errorNumber,
            $errorMessage,
            5.0,
        );
        if ($client === false) {
            throw new RuntimeException('Unable to connect: ' . $errorMessage);
        }

        return $client;
    }

    /**
     * Reads responses until one answers the message ID, returning its result code, or null when none arrives in time.
     *
     * @param resource $client
     */
    private function resultCodeFor(
        $client,
        int $messageId,
    ): ?int {
        $decoder = Container::forClient(new ClientOptions())->get(ResponseMessageDecoder::class);
        $encoder = new LdapEncoder();
        $buffer = '';
        $deadline = microtime(true) + self::RESPONSE_WAIT_SECONDS;
        stream_set_timeout(
            $client,
            1,
        );

        while (microtime(true) < $deadline) {
            $message = self::nextMessage(
                $encoder,
                $decoder,
                $buffer,
            );
            if ($message === null) {
                $bytes = fread(
                    $client,
                    65_536,
                );
                if ($bytes === false || ($bytes === '' && feof($client))) {
                    return null;
                }
                $buffer .= $bytes;

                continue;
            }

            $response = $message->getMessageId() === $messageId
                ? $message->getResponse()
                : null;
            if ($response instanceof LdapResult) {
                return $response->getResultCode();
            }
        }

        return null;
    }

    /**
     * Takes the next whole message off the buffer, or null until one has fully arrived.
     */
    private static function nextMessage(
        LdapEncoder $encoder,
        ResponseMessageDecoder $decoder,
        string &$buffer,
    ): ?LdapMessageResponse {
        if ($buffer === '') {
            return null;
        }

        try {
            $pdu = $encoder->decode($buffer);
        } catch (PartialPduException) {
            return null;
        }
        $buffer = substr(
            $buffer,
            (int) $encoder->getLastPosition(),
        );

        return $decoder->decode($pdu);
    }

    private static function encodedRequest(LdapMessageRequest $request): string
    {
        return (new LdapEncoder())->encode($request->toAsn1());
    }

    /**
     * A search under 4 KiB whose 200-item filter the server estimates to hold about 100 KB.
     */
    private static function searchHoldingManyElements(): SearchRequest
    {
        return Operations::search(Filters::or(
            Filters::present('objectClass'),
            ...array_map(
                static fn(int $i): FilterInterface => Filters::equal(
                    'cn',
                    "absent-{$i}",
                ),
                range(
                    1,
                    200,
                ),
            ),
        ))->base('dc=foo,dc=bar');
    }
}
