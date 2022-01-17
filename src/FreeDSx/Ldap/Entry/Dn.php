<?php

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
class Dn implements IteratorAggregate, Countable
{
    /**
     * @var string
     */
    protected $dn;

    /**
     * @var null|Rdn[]
     */
    protected $pieces;

    /**
     * @param string $dn
     */
    public function __construct(string $dn)
    {
        $this->dn = $dn;
    }

    /**
     * @return Rdn
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
     * @return null|Dn
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
     * @@psalm-return \ArrayIterator<array-key, Rdn>
     * @throws UnexpectedValueException
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->toArray());
    }

    /**
     * @return string
     */
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
     * @return string
     */
    public function __toString()
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

    /**
     * @param string $dn
     * @return bool
     */
    public static function isValid(string $dn): bool
    {
        try {
            (new self($dn))->toArray();

            return true;
        } catch (UnexpectedValueException | InvalidArgumentException $e) {
            return false;
        }
    }

    /**
     * @todo This needs proper handling. But the regex would probably be rather crazy.
     *
     * @throws UnexpectedValueException
     */
    protected function parse(): void
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
