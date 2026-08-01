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

use FreeDSx\Ldap\Schema\Text;
use Normalizer;

/**
 * Pragmatic RFC 4518 string preparation shared by the case-ignore and case-exact comparators.
 */
final readonly class StringPrep
{
    /**
     * Code points removed by the Map step (RFC 4518 §2.2): soft hyphen, zero-width, variation selectors, NULL.
     */
    private const MAP_TO_NOTHING = '/[\x{00AD}\x{034F}\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}\x{180B}-\x{180D}\x{FE00}-\x{FE0F}\x{0000}]/u';

    /**
     * Whitespace variants folded to SPACE by the Map step (RFC 4518 §2.2).
     */
    private const MAP_TO_SPACE = '/[\x{0009}-\x{000D}\x{0085}\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]/u';

    private bool $canFoldUnicode;

    private bool $canNormalize;

    public function __construct(
        public bool $foldCase = true,
    ) {
        $this->canFoldUnicode = function_exists('mb_strtolower');
        $this->canNormalize = class_exists(Normalizer::class);
    }

    /**
     * Canonical form for equality, ordering, and the substring value side.
     */
    public function prepareForEquality(string $value): string
    {
        return $this->prepare(
            $value,
            trim: true,
        );
    }

    /**
     * Substring fragment prep: interior spaces collapse but leading/trailing spaces are preserved.
     */
    public function prepareFragment(string $fragment): string
    {
        return $this->prepare(
            $fragment,
            trim: false,
        );
    }

    private function prepare(
        string $value,
        bool $trim,
    ): string {
        if (!Text::isUtf8($value)) {
            return $this->prepareRawBytes(
                $value,
                $trim,
            );
        }

        $prepared = $this->normalize($this->caseFold($this->map($value)));

        return $this->squeeze(
            $prepared,
            $trim,
        );
    }

    private function prepareRawBytes(
        string $value,
        bool $trim,
    ): string {
        $folded = $this->foldCase
            ? strtolower($value)
            : $value;

        return $this->squeeze(
            $folded,
            $trim,
        );
    }

    private function map(string $value): string
    {
        $stripped = preg_replace(
            self::MAP_TO_NOTHING,
            '',
            $value,
        ) ?? $value;

        return preg_replace(
            self::MAP_TO_SPACE,
            ' ',
            $stripped,
        ) ?? $stripped;
    }

    private function caseFold(string $value): string
    {
        if (!$this->foldCase) {
            return $value;
        }

        if ($this->canFoldUnicode) {
            return mb_strtolower(
                $value,
                'UTF-8',
            );
        }

        return strtolower($value);
    }

    private function normalize(string $value): string
    {
        if (!$this->canNormalize) {
            return $value;
        }

        $normalized = Normalizer::normalize(
            $value,
            Normalizer::FORM_KC,
        );

        return is_string($normalized)
            ? $normalized
            : $value;
    }

    private function squeeze(
        string $value,
        bool $trim,
    ): string {
        $collapsed = preg_replace(
            '/ +/',
            ' ',
            $value,
        ) ?? $value;

        if (!$trim) {
            return $collapsed;
        }

        return trim(
            $collapsed,
            ' ',
        );
    }
}
