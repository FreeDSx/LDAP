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

namespace Tests\Support\FreeDSx\Ldap\Protocol;

use Closure;
use Error;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessage;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use Throwable;

use function array_map;
use function implode;
use function sha1;
use function sprintf;
use function strrchr;
use function substr;

/**
 * Describes what decoding one PDU produced, in a form stable enough to compare across changes to the decoders.
 */
final class DecodeOutcome
{
    /**
     * @param Closure(string): LdapMessage $decode
     */
    public static function of(
        Closure $decode,
        string $ber,
    ): string {
        try {
            $message = $decode($ber);
        } catch (MessageDecodeException $e) {
            return sprintf(
                'MessageDecodeException(id=%d, tag=%d, result=%d) %s',
                $e->getMessageId(),
                $e->getProtocolOpTag(),
                $e->getResultCode(),
                $e->getMessage(),
            );
        } catch (Error $e) {
            // An engine error names files and lines, which move with the code, so only its kind is recorded.
            return self::shortName($e::class);
        } catch (Throwable $e) {
            return sprintf(
                '%s(%d) %s',
                self::shortName($e::class),
                $e->getCode(),
                $e->getMessage(),
            );
        }

        return sprintf(
            '%s %s [%s] %s',
            self::shortName($message::class),
            self::shortName(self::operationOf($message)::class),
            implode(
                ',',
                array_map(
                    static fn(object $control): string => self::shortName($control::class),
                    $message->controls()->toArray(),
                ),
            ),
            self::reencoded($message),
        );
    }

    private static function operationOf(LdapMessage $message): object
    {
        if ($message instanceof LdapMessageRequest) {
            return $message->getRequest();
        }
        if ($message instanceof LdapMessageResponse) {
            return $message->getResponse();
        }

        return $message;
    }

    private static function reencoded(LdapMessage $message): string
    {
        try {
            return substr(
                sha1((new LdapEncoder())->encode($message->toAsn1())),
                0,
                12,
            );
        } catch (Throwable $e) {
            return 'unencodable ' . self::shortName($e::class);
        }
    }

    private static function shortName(string $class): string
    {
        $short = strrchr(
            $class,
            '\\',
        );

        return $short === false
            ? $class
            : substr(
                $short,
                1,
            );
    }
}
