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

namespace FreeDSx\Ldap\Schema\Matching;

/**
 * The two components of an RFC 4517 §3.3.21 value: a distinguished name and the identifier that may follow it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class NameAndOptionalUid
{
    /**
     * The DN carries its own unescaped '#', so only a bit string running to the end of the value closes it.
     */
    private const PATTERN = "/^(?<name>.*?)#(?<uid>'[01]*'[Bb])$/D";

    private function __construct(
        public string $name,
        public ?string $uid,
    ) {}

    public static function parse(string $value): self
    {
        if (preg_match(self::PATTERN, $value, $matches) !== 1) {
            return new self($value, null);
        }

        return new self(
            $matches['name'],
            $matches['uid'],
        );
    }
}
