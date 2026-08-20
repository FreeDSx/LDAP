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

namespace FreeDSx\Ldap\Schema\Matching\Comparator;

/**
 * Index forms for a rule that removes insignificant characters outright, leaving nothing for trimming to change.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait NormalizedIndexFormsTrait
{
    public function indexKey(string $value): ?string
    {
        return $this->normalize($value);
    }

    public function indexFragment(string $fragment): ?string
    {
        return $this->normalize($fragment);
    }

    abstract private function normalize(string $value): string;
}
