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

namespace FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\Schema\Matching\StringPrep;
use FreeDSx\Ldap\Schema\Text;

use function count;
use function implode;
use function preg_replace;
use function sort;
use function strtolower;
use function trim;

/**
 * Canonicalizes a DN for comparison and keying using the pragmatic RFC 4518 caseIgnore profile.
 */
final class DnNormalizer
{
    private static ?self $instance = null;

    private readonly StringPrep $prep;

    public function __construct()
    {
        $this->prep = new StringPrep(foldCase: true);
    }

    /**
     * Canonical DN form.
     *
     * Escapes resolved before folding (RFC 4514 4) and reapplied after.
     */
    public static function canonicalize(string $dn): string
    {
        return (self::$instance ??= new self())->doCanonicalize($dn);
    }

    private function doCanonicalize(string $dn): string
    {
        if ($dn === '') {
            return '';
        }

        try {
            $rdns = (new Dn($dn))->toArray();
        } catch (UnexpectedValueException|InvalidArgumentException) {
            return strtolower($dn);
        }

        $ascii = Text::isAscii($dn);
        $parts = [];
        foreach ($rdns as $rdn) {
            $parts[] = $this->canonicalizeRdn(
                $rdn,
                $ascii,
            );
        }

        return implode(
            ',',
            $parts,
        );
    }

    private function canonicalizeRdn(
        Rdn $rdn,
        bool $ascii,
    ): string {
        $components = [];

        foreach ($rdn->getAll() as $component) {
            $components[] = strtolower(trim($component->getName()))
                . '='
                . $this->canonicalizeValue(
                    $component->getValue(),
                    $ascii,
                );
        }

        // Components of a multivalued RDN are an unordered set. Sort for a stable canonical form.
        if (count($components) > 1) {
            sort($components);
        }

        return implode(
            '+',
            $components,
        );
    }

    private function canonicalizeValue(
        string $value,
        bool $ascii,
    ): string {
        $resolved = Rdn::unescape($value);
        $folded = $ascii && Text::isAscii($resolved)
            ? $this->canonicalizeAsciiValue($resolved)
            : $this->prep->prepareForEquality($resolved);

        return Rdn::escape($folded);
    }

    /**
     * Applies the same RFC 4518 2.2 mapping the prep profile would.
     */
    private function canonicalizeAsciiValue(string $value): string
    {
        $lowered = strtolower($value);
        $folded = preg_replace(
            '/[\x00-\x08\x0E-\x1F\x7F]/',
            '',
            $lowered,
        ) ?? $lowered;
        $collapsed = preg_replace(
            '/[\x09-\x0D ]+/',
            ' ',
            $folded,
        ) ?? $folded;

        return trim(
            $collapsed,
            ' ',
        );
    }
}
