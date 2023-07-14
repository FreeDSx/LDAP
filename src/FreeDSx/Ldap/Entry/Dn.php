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
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use IteratorAggregate;
use Stringable;
use Traversable;
use function array_slice;
use function count;
use function implode;
use function ltrim;
use function preg_split;

/**
 * Represents a Distinguished Name.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Dn implements IteratorAggregate, Countable, Stringable
{
    private ?array $pieces = null;

    public function __construct(private readonly string $dn)
    {
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

    public function __toString(): string
    {
        return $this->dn;
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
        } catch (UnexpectedValueException | InvalidArgumentException) {
            return false;
        }
    }

    /**
     * @todo This needs proper handling. But the regex would probably be rather crazy.
     *
     * @throws UnexpectedValueException
     */
    private function parse(): void
    {
        if ($this->dn === '') {
            $this->pieces = [];

            return;
        }
        $pieces = preg_split('/(?<!\\\\),/', $this->dn);
        $pieces = ($pieces === false) ? [] : $pieces;

        if (count($pieces) === 0) {
            throw new UnexpectedValueException(sprintf(
                'The DN value "%s" is not valid.',
                $this->dn
            ));
        }

        $rdns = [];
        foreach ($pieces as $i => $piece) {
            $rdns[$i] = Rdn::create(ltrim($piece));
        }

        $this->pieces = $rdns;
    }
}
