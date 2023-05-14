<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Operation\Response\SyncInfo;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;

trait SyncRefreshDoneTrait
{
    /**
     * @var bool
     */
    protected $refreshDone;

    /**
     * @param bool $refreshDone
     * @param string|null $cookie
     */
    public function __construct(
        bool $refreshDone = true,
        ?string $cookie = null
    ) {
        $this->refreshDone = $refreshDone;
        parent::__construct($cookie);
    }

    /**
     * @return bool
     */
    public function getRefreshDone() : bool
    {
        return $this->refreshDone;
    }

    /**
     * @param bool $refreshDone
     * @return $this
     */
    public function setRefreshDone(bool $refreshDone)
    {
        $this->refreshDone = $refreshDone;

        return $this;
    }

    /**
     *{@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->responseValue = Asn1::context(static::VALUE_TAG, Asn1::sequence());
        if ($this->cookie !== null) {
            $this->responseValue->addChild(Asn1::octetString($this->cookie));
        }
        $this->responseValue->addChild(Asn1::boolean($this->refreshDone));

        return parent::toAsn1();
    }

    /**
     *{@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $responseName = self::decodeResponseName($type);
        $responseValue = self::decodeEncodedValue($type, [AbstractType::TAG_CLASS_CONTEXT_SPECIFIC => [self::VALUE_TAG => AbstractType::TAG_TYPE_SEQUENCE]]);
        if (!($responseValue instanceof SequenceType && \count($type->getChildren()) < 3)) {
            throw new ProtocolException('Expected a sequence type with 2 or less children for a refreshPresent.');
        }

        $cookie = null;
        $refreshDone = true;
        foreach ($responseValue->getChildren() as $child) {
            if ($child instanceof OctetStringType) {
                $cookie = $child->getValue();
            } elseif ($child instanceof BooleanType) {
                $refreshDone = $child->getValue();
            } else {
                throw new ProtocolException('Unexpected value in the refreshPresent response.');
            }
        }
        $syncRefresh = new self($refreshDone, $cookie);
        $syncRefresh->responseName = $responseName;

        return $syncRefresh;
    }
}
