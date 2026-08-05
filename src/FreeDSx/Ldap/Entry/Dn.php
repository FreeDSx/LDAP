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

use ArrayIterator;
use Countable;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\InvalidDnSyntaxException;
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use IteratorAggregate;
use Stringable;
use Traversable;

use function array_slice;
use function count;
use function implode;
use function ltrim;
use function str_ends_with;
use function strlen;
use function strpos;
use function substr;

/**
 * Represents a Distinguished Name.
 *
 * @implements IteratorAggregate<Rdn>
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Dn implements IteratorAggregate, Countable, Stringable
{
    use UnescapedSeparatorTrait;

    /**
     * @var ?Rdn[]
     */
    private ?array $pieces = null;

    private ?Dn $normalized = null;

    public function __construct(private readonly string $dn) {}

    public function __toString(): string
    {
        return $this->dn;
    }

    /**
     * Wrap an already-canonical DN string, skipping re-normalization.
     */
    public static function fromCanonical(string $canonical): self
    {
        $dn = new self($canonical);
        $dn->normalized = $dn;

        return $dn;
    }

    /**
     * Where an RDN sits under $parent, or at the root when there is none.
     */
    public static function fromRdn(
        Rdn $rdn,
        ?Dn $parent = null,
    ): self {
        return $parent === null
            ? new self($rdn->toString())
            : new self($rdn->toString() . ',' . $parent->toString());
    }

    /**
     * @throws UnexpectedValueException
     */
    public function getRdn(): Rdn
    {
        if ($this->pieces === null) {
            $this->parse();
        }
        if (!isset($this->pieces[0])) {
            throw new UnexpectedValueException('The DN has no RDN.');
        }

        return $this->pieces[0];
    }

    /**
     * @throws UnexpectedValueException
     */
    public function getParent(): ?Dn
    {
        if ($this->pieces === null) {
            $this->parse();
        }
        if (count((array) $this->pieces) < 2) {
            return null;
        }

        return new Dn(implode(',', array_slice((array) $this->pieces, 1)));
    }

    /**
     * @inheritDoc
     * @return Traversable<Rdn>
     * @throws UnexpectedValueException
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->toArray());
    }

    public function toString(): string
    {
        return $this->dn;
    }

    /**
     * @inheritDoc
     * @psalm-return 0|positive-int
     * @throws UnexpectedValueException
     */
    public function count(): int
    {
        if ($this->pieces === null) {
            $this->parse();
        }

        return count((array) $this->pieces);
    }

    /**
     * @return Rdn[]
     * @throws UnexpectedValueException
     */
    public function toArray(): array
    {
        if ($this->pieces !== null) {
            return $this->pieces;
        }
        $this->parse();

        return ($this->pieces === null) ? [] : $this->pieces;
    }

    public static function isValid(Stringable|string $dn): bool
    {
        try {
            (new self((string) $dn))->toArray();

            return true;
        } catch (UnexpectedValueException|InvalidArgumentException) {
            return false;
        }
    }

    /**
     * Return the canonical (RFC 4518 caseIgnore) copy of this DN.
     */
    public function normalize(): Dn
    {
        if ($this->normalized !== null) {
            return $this->normalized;
        }
        $canonical = DnNormalizer::canonicalize($this->dn);

        return $this->normalized = $canonical === $this->dn
            ? $this
            : self::fromCanonical($canonical);
    }

    /**
     * Return true if this DN is a direct child of $parent.
     *
     * @throws UnexpectedValueException
     */
    public function isChildOf(Dn $parent): bool
    {
        $thisDn = $this->normalize()->toString();

        if ($thisDn === '') {
            return false;
        }

        return self::canonicalParent($thisDn) === $parent->normalize()->toString();
    }

    /**
     * Return true if this DN is the same as, or a descendant of, $base.
     *
     * @throws UnexpectedValueException
     */
    public function isDescendantOf(Dn $base): bool
    {
        $baseDn = $base->normalize()->toString();
        $thisDn = $this->normalize()->toString();

        if ($baseDn === '') {
            return $thisDn !== '';
        }
        if ($thisDn === $baseDn) {
            return true;
        }
        $ancestorSuffix = ',' . $baseDn;

        return str_ends_with($thisDn, $ancestorSuffix)
            && self::isUnescapedAt($thisDn, strlen($thisDn) - strlen($ancestorSuffix));
    }

    /**
     * Parent of an already-canonical DN: the substring after the first unescaped RDN separator.
     */
    private static function canonicalParent(string $canonical): string
    {
        $offset = 0;
        while (($pos = strpos($canonical, ',', $offset)) !== false) {
            if (self::isUnescapedAt($canonical, $pos)) {
                return substr($canonical, $pos + 1);
            }
            $offset = $pos + 1;
        }

        return '';
    }

    /**
     * @throws UnexpectedValueException
     */
    private function parse(): void
    {
        if ($this->dn === '') {
            $this->pieces = [];

            return;
        }
        $pieces = self::splitOnUnescaped($this->dn, ',');

        if (count($pieces) === 0) {
            throw new InvalidDnSyntaxException(sprintf(
                'The DN value "%s" is not valid.',
                $this->dn,
            ));
        }

        $rdns = [];
        foreach ($pieces as $i => $piece) {
            $rdns[$i] = Rdn::create(ltrim($piece));
        }

        $this->pieces = $rdns;
    }
}
