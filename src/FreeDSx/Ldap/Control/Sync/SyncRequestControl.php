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
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Search\SyncHandlerInterface;

/**
 * Represents a syncRequestValue control. RFC 4533.
 *
 * syncRequestValue ::= SEQUENCE {
 *     mode ENUMERATED {
 *         -- 0 unused
 *         refreshOnly       (1),
 *         -- 2 reserved
 *         refreshAndPersist (3)
 *     },
 *     cookie     syncCookie OPTIONAL,
 *     reloadHint BOOLEAN DEFAULT FALSE
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com
 * @see https://tools.ietf.org/html/rfc4533
 */
class SyncRequestControl extends Control
{
    public const MODE_REFRESH_ONLY = 1;

    public const MODE_REFRESH_AND_PERSIST = 3;

    /**
     * @var int
     */
    protected $mode;

    /**
     * @var string|null
     */
    protected $cookie;

    /**
     * @var bool
     */
    protected $reloadHint = false;

    /**
     * @var SyncHandlerInterface|null
     */
    protected $syncHandler;

    /**
     * @param int $mode
     * @param string|null $cookie
     * @param bool|null $reloadHint
     */
    public function __construct(
        int $mode = self::MODE_REFRESH_ONLY,
        ?string $cookie = null,
        bool $reloadHint = false
    ) {
        $this->mode = $mode;
        $this->cookie = $cookie;
        $this->reloadHint = $reloadHint;
        parent::__construct(
            self::OID_SYNC_REQUEST,
            true
        );
    }

    /**
     * @return int
     */
    public function getMode() : int
    {
        return $this->mode;
    }

    /**
     * @param int $mode
     * @return $this
     */
    public function setMode(int $mode): self
    {
        $this->mode = $mode;

        return $this;
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
    public function setCookie($cookie)
    {
        $this->cookie = $cookie;

        return $this;
    }

    /**
     * @return bool
     */
    public function getReloadHint() : bool
    {
        return $this->reloadHint;
    }

    /**
     * @param bool|null $reloadHint
     * @return $this
     */
    public function setReloadHint(?bool $reloadHint): self
    {
        $this->reloadHint = $reloadHint;

        return $this;
    }

    /**
     * @return SyncHandlerInterface|null
     */
    public function getSyncHandler() : ?SyncHandlerInterface
    {
        return $this->syncHandler;
    }

    /**
     * @param SyncHandlerInterface|null $handler
     * @return $this
     */
    public function setSyncHandler(?SyncHandlerInterface $handler): self
    {
        $this->syncHandler = $handler;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequence(Asn1::enumerated($this->mode));
        if ($this->cookie !== null) {
            $this->controlValue->addChild(Asn1::octetString($this->cookie));
        }
        $this->controlValue->addChild(Asn1::boolean($this->reloadHint));

        return parent::toAsn1();
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $sync = self::decodeEncodedValue($type);
        if (!($sync instanceof SequenceType && \count($sync->getChildren()) <= 3)) {
            throw new ProtocolException('Expected a sequence type with 2 or less values for a sync request control value.');
        }

        $cookie = null;
        $mode = null;
        $reloadHint = false;
        foreach ($sync->getChildren() as $child) {
            if ($child instanceof OctetStringType) {
                $cookie = $child->getValue();
            } elseif ($child instanceof BooleanType) {
                $reloadHint = $child->getValue();
            } elseif ($child instanceof EnumeratedType) {
                $mode = $child->getValue();
            }
        }

        if ($mode === null) {
            throw new ProtocolException('Expected an enumerated type for the sync request mode.');
        }

        return self::mergeControlData(new self($mode, $cookie, $reloadHint), $type);
    }
}
