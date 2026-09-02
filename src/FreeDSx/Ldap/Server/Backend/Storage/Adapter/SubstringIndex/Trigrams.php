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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex;

use FreeDSx\Ldap\Schema\Text;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;

/**
 * Extracts the distinct 3-character windows (trigrams) of a value for substring-index candidate narrowing.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class Trigrams
{
    private const SIZE = 3;

    /**
     * Whether the trigrams of a value cover all of it.
     */
    public static function covers(string $value): bool
    {
        return Text::isUtf8($value)
            && mb_strlen(
                mb_strtolower($value, 'UTF-8'),
                'UTF-8',
            ) <= SqlFilterUtility::MAX_INDEXED_VALUE_CHARS;
    }

    /**
     * Distinct trigrams of the folded (lowercased, truncated) value; empty for non-UTF-8 or values shorter than 3 chars.
     *
     * @return list<string>
     */
    public static function of(string $value): array
    {
        if (!Text::isUtf8($value)) {
            return [];
        }

        $folded = mb_substr(
            mb_strtolower($value, 'UTF-8'),
            0,
            SqlFilterUtility::MAX_INDEXED_VALUE_CHARS,
            'UTF-8',
        );

        $chars = mb_str_split($folded, 1, 'UTF-8');
        $count = count($chars);

        if ($count < self::SIZE) {
            return [];
        }

        $grams = [];
        for ($i = 0; $i + self::SIZE <= $count; $i++) {
            $grams[] = $chars[$i] . $chars[$i + 1] . $chars[$i + 2];
        }

        return array_values(array_unique($grams));
    }
}
