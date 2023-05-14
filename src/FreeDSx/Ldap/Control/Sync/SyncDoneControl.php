<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Control\Sync;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Represents a syncStateValue control. RFC 4533.
 *
 * syncDoneValue ::= SEQUENCE {
 *     cookie          syncCookie OPTIONAL,
 *     refreshDeletes  BOOLEAN DEFAULT FALSE
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com
 * @see https://tools.ietf.org/html/rfc4533
 */
class SyncDoneControl extends Control
{
    /**
     * @var null|string
     */
    protected $cookie;

    /**
     * @var bool
     */
    protected $refreshDeletes;

    /**
     * @param string|null $cookie
     * @param bool|null $refreshDeletes
     */
    public function __construct(
        ?string $cookie = null,
        bool $refreshDeletes = false
    ) {
        $this->cookie = $cookie;
        $this->refreshDeletes = $refreshDeletes;
        parent::__construct(self::OID_SYNC_DONE, true);
    }

    /**
     * @return string|null
     */
    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    /**
     * @param string|null $cookie
     * @return $this
     */
    public function setCookie(?string $cookie)
    {
        $this->cookie = $cookie;

        return $this;
    }

    /**
     * @return bool
     */
    public function getRefreshDeletes() : ?bool
    {
        return $this->refreshDeletes;
    }

    /**
     * @param bool $refreshDeletes
     * @return $this
     */
    public function setRefreshDeletes(bool $refreshDeletes): self
    {
        $this->refreshDeletes = $refreshDeletes;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequence();
        if ($this->cookie !== null) {
            $this->controlValue->addChild(Asn1::octetString($this->cookie));
        }
        $this->controlValue->addChild(Asn1::boolean($this->refreshDeletes ?? false));

        return parent::toAsn1();
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $sync = self::decodeEncodedValue($type);
        if (!($sync instanceof SequenceType && \count($sync->getChildren()) <= 2)) {
            throw new ProtocolException('Expected a sequence type with 2 or less values for a sync done control value.');
        }

        $cookie = null;
        $refreshDeletes = false;
        foreach ($sync->getChildren() as $child) {
            if ($child instanceof OctetStringType) {
                $cookie = $child->getValue();
            } elseif ($child instanceof BooleanType) {
                $refreshDeletes = $child->getValue();
            }
        }

        return self::mergeControlData(new self($cookie, $refreshDeletes), $type);
    }
}
