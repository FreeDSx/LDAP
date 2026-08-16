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
     * Code points removed by the Map step (RFC 4518 §2.2).
     */
    private const MAP_TO_NOTHING = '/['
        // Controls, less the line breaking ones mapped to SPACE below.
        . '\x{0000}-\x{0008}\x{000E}-\x{001F}\x{007F}-\x{0084}\x{0086}-\x{009F}'
        // Soft hyphens, combining grapheme joiner, variation selectors.
        . '\x{00AD}\x{034F}\x{06DD}\x{070F}\x{1806}\x{180B}-\x{180E}\x{FE00}-\x{FE0F}'
        // Zero width space and the bidi formatting points, which otherwise render identically to nothing.
        . '\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2063}\x{206A}-\x{206F}\x{FEFF}'
        // Annotation marks, object replacement, and the musical and tag formatting points.
        . '\x{FFF9}-\x{FFFC}\x{1D173}-\x{1D17A}\x{E0001}\x{E0020}-\x{E007F}'
        . ']/u';

    /**
     * Whitespace folded to SPACE by the Map step (RFC 4518 §2.2).
     */
    private const MAP_TO_SPACE = '/['
        // Line breaking controls.
        . '\x{0009}-\x{000D}\x{0085}'
        // Every code point carrying a Separator property.
        . '\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}-\x{2029}\x{202F}\x{205F}\x{3000}'
        . ']/u';

    private bool $canFoldUnicode;

    private bool $canNormalize;

    public function __construct(
        public bool $foldCase = true,
    ) {
        $this->canFoldUnicode = function_exists('mb_convert_case');
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

    /**
     * RFC 4518 2.3 calls for RFC 3454 B.2 case folding, which is not lowercasing: folding maps German sharp s
     * to "ss" so that it compares equal to the spelled-out form.
     */
    private function caseFold(string $value): string
    {
        if (!$this->foldCase) {
            return $value;
        }

        if ($this->canFoldUnicode) {
            return mb_convert_case(
                $value,
                MB_CASE_FOLD,
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
