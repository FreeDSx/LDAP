<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Exception\UrlParseException;
use function explode;
use function str_ireplace;
use function str_replace;
use function substr;

/**
 * Represents a LDAP URL extension component. RFC 4516, Section 2.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapUrlExtension
{
    use LdapUrlTrait;

    private string $name;

    private ?string $value;

    private bool $isCritical;

    public function __construct(
        string $name,
        ?string $value = null,
        bool $isCritical = false
    ) {
        $this->name = $name;
        $this->value = $value;
        $this->isCritical = $isCritical;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): self
    {
        $this->name = $name;

        return $this;
    }

    public function getValue(): ?string
    {
        return $this->value;
    }

    public function setValue(?string $value): self
    {
        $this->value = $value;

        return $this;
    }

    public function getIsCritical(): bool
    {
        return $this->isCritical;
    }

    public function setIsCritical(bool $isCritical): self
    {
        $this->isCritical = $isCritical;

        return $this;
    }

    public function toString(): string
    {
        $ext = ($this->isCritical ? '!' : '') . str_replace(',', '%2c', self::encode($this->name));

        if ($this->value !== null) {
            $ext .= '=' . str_replace(',', '%2c', self::encode($this->value));
        }

        return $ext;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * @throws UrlParseException
     */
    public static function parse(string $extension): LdapUrlExtension
    {
        if (preg_match('/!?\w+(=.*)?/', $extension) !== 1) {
            throw new UrlParseException(sprintf('The LDAP URL extension is malformed: %s', $extension));
        }
        $pieces = explode('=', $extension, 2);

        $isCritical = isset($pieces[0][0]) && $pieces[0][0] === '!';
        if ($isCritical) {
            $pieces[0] = substr($pieces[0], 1);
        }

        $name = str_ireplace('%2c', ',', self::decode($pieces[0]));
        $value = isset($pieces[1]) ? str_ireplace('%2c', ',', self::decode($pieces[1])) : null;

        return new self(
            $name,
            $value,
            $isCritical
        );
    }
}
