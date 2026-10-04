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

namespace FreeDSx\Ldap\Server\Process;

use FreeDSx\Ldap\Exception\RuntimeException;

use function explode;
use function fclose;
use function fmod;
use function fread;
use function fwrite;
use function is_array;
use function is_resource;
use function json_decode;
use function json_encode;
use function microtime;
use function stream_select;
use function stream_set_blocking;
use function stream_socket_pair;
use function strrpos;
use function substr;

/**
 * A framed message channel between the parent and child process over a socket pair.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ChildChannel
{
    private const FRAME_DELIMITER = "\n";

    private const READ_CHUNK_SIZE = 8192;

    /**
     * @var resource
     */
    private $readEnd;

    /**
     * @var resource
     */
    private $writeEnd;

    private string $readBuffer = '';

    /**
     * Frames the socket has not taken yet.
     */
    private string $writeBuffer = '';

    /**
     * @param resource $readEnd
     * @param resource $writeEnd
     */
    public function __construct(
        $readEnd,
        $writeEnd,
        private readonly ChannelMessageFactory $messageFactory,
    ) {
        $this->readEnd = $readEnd;
        $this->writeEnd = $writeEnd;
    }

    /**
     * @throws RuntimeException
     */
    public static function create(ChannelMessageFactory $messageFactory): self
    {
        $pair = stream_socket_pair(
            STREAM_PF_UNIX,
            STREAM_SOCK_STREAM,
            0,
        );

        if ($pair === false) {
            throw new RuntimeException('Unable to create a child process channel.');
        }

        stream_set_blocking(
            $pair[0],
            false,
        );
        stream_set_blocking(
            $pair[1],
            false,
        );

        return new self(
            $pair[0],
            $pair[1],
            $messageFactory,
        );
    }

    /**
     * Keep the write end in the child; the read end belongs to the parent.
     */
    public function childKeepWrite(): void
    {
        if (is_resource($this->readEnd)) {
            fclose($this->readEnd);
        }
    }

    /**
     * Keep the read end in the parent; the write end belongs to the child.
     */
    public function parentKeepRead(): void
    {
        if (is_resource($this->writeEnd)) {
            fclose($this->writeEnd);
        }
    }

    /**
     * @return bool whether nothing is left pending
     */
    public function send(ChannelMessage $message): bool
    {
        if (!is_resource($this->writeEnd)) {
            return false;
        }

        $encoded = json_encode($message->toArray());
        if ($encoded === false) {
            return $this->flush();
        }
        $this->writeBuffer .= $encoded . self::FRAME_DELIMITER;

        return $this->flush();
    }

    /**
     * Writes as much of the pending frames as the socket takes without blocking.
     *
     * @return bool whether nothing is left pending
     */
    public function flush(): bool
    {
        while ($this->writeBuffer !== '' && is_resource($this->writeEnd)) {
            $written = fwrite(
                $this->writeEnd,
                $this->writeBuffer,
            );

            if ($written === false || $written === 0) {
                return false;
            }

            $this->writeBuffer = substr(
                $this->writeBuffer,
                $written,
            );
        }

        return $this->writeBuffer === '';
    }

    /**
     * Waits up to the timeout for the pending frames to be written.
     *
     * @return bool whether nothing is left pending
     */
    public function drain(float $timeoutSeconds): bool
    {
        $deadline = microtime(true) + $timeoutSeconds;

        while (!$this->flush()) {
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0 || !is_resource($this->writeEnd)) {
                return false;
            }

            $this->awaitWritable($remaining);
        }

        return true;
    }

    /**
     * Non-blocking drain of any complete messages currently available.
     *
     * @return list<ChannelMessage>
     */
    public function receive(): array
    {
        $this->fillReadBuffer();

        $boundary = strrpos(
            $this->readBuffer,
            self::FRAME_DELIMITER,
        );
        if ($boundary === false) {
            return [];
        }

        $complete = substr(
            $this->readBuffer,
            0,
            $boundary,
        );
        $this->readBuffer = substr(
            $this->readBuffer,
            $boundary + 1,
        );

        $messages = [];
        foreach (explode(self::FRAME_DELIMITER, $complete) as $frame) {
            if ($frame === '') {
                continue;
            }

            $decoded = json_decode(
                $frame,
                associative: true,
            );
            if (!is_array($decoded)) {
                continue;
            }

            $messages[] = $this->messageFactory->fromArray($decoded);
        }

        return $messages;
    }

    /**
     * Close the write end so the parent observes EOF after the final message.
     */
    public function closeWrite(): void
    {
        if (is_resource($this->writeEnd)) {
            fclose($this->writeEnd);
        }
    }

    public function close(): void
    {
        if (is_resource($this->readEnd)) {
            fclose($this->readEnd);
        }

        if (is_resource($this->writeEnd)) {
            fclose($this->writeEnd);
        }
    }

    private function fillReadBuffer(): void
    {
        if (!is_resource($this->readEnd)) {
            return;
        }

        while (true) {
            $chunk = fread($this->readEnd, self::READ_CHUNK_SIZE);
            if ($chunk === false || $chunk === '') {
                break;
            }

            $this->readBuffer .= $chunk;
        }
    }

    private function awaitWritable(float $seconds): void
    {
        $read = null;
        $write = [$this->writeEnd];
        $except = null;

        @stream_select(
            $read,
            $write,
            $except,
            (int) $seconds,
            (int) (fmod($seconds, 1.0) * 1_000_000),
        );
    }
}
