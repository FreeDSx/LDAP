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
use function count;

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

    private int $mode;

    private ?string $cookie;

    private bool $reloadHint;

    private ?SyncHandlerInterface $syncHandler = null;

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

    public function getMode(): int
    {
        return $this->mode;
    }

    public function setMode(int $mode): self
    {
        $this->mode = $mode;

        return $this;
    }

    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    public function setCookie(?string $cookie): self
    {
        $this->cookie = $cookie;

        return $this;
    }

    public function getReloadHint(): bool
    {
        return $this->reloadHint;
    }

    public function setReloadHint(bool $reloadHint): self
    {
        $this->reloadHint = $reloadHint;

        return $this;
    }

    public function getSyncHandler(): ?SyncHandlerInterface
    {
        return $this->syncHandler;
    }

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
    public static function fromAsn1(AbstractType $type): static
    {
        $sync = self::decodeEncodedValue($type);
        if (!$sync instanceof SequenceType || count($sync->getChildren()) > 3) {
            throw new ProtocolException(
                'Expected a sequence type with 2 or less values for a sync request control value.'
            );
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

        return self::mergeControlData(
            new static(
                $mode,
                $cookie,
                $reloadHint
            ),
            $type
        );
    }
}
