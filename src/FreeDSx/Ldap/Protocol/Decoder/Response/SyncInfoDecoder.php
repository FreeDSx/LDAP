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

namespace FreeDSx\Ldap\Protocol\Decoder\Response;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Asn1\Type\SetType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshPresent;
use FreeDSx\Ldap\Operation\Response\SyncInfoMessage;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\FieldValueTrait;

use function count;
use function is_string;
use function sprintf;

/**
 * Decodes the sync info message (RFC 4533 2.5) an intermediate response carries, in each of its four forms.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SyncInfoDecoder
{
    use FieldValueTrait;

    private const MALFORMED_NAME = 'Expected a responseName value with a tag of 0 and a context specific class type.';

    private const MALFORMED_VALUE = 'The intermediate response either contains no value or is not an octet string.';

    private const MALFORMED_SEQUENCE = 'Expected a sequence type with 2 or less children for a refreshPresent.';

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): SyncInfoMessage {
        if ($type->getChild(1) === null) {
            throw new ProtocolException('The SyncInfoMessage must have a value.');
        }

        // The CHOICE is read first, then the form it names is decoded again with the tag that form maps.
        $choice = $this->valueOf(
            $type,
            $context,
        );

        return match ($choice->getTagNumber()) {
            0 => $this->newCookie(
                $type,
                $context,
            ),
            1 => $this->refreshDone(
                SyncRefreshDelete::class,
                1,
                $type,
                $context,
            ),
            2 => $this->refreshDone(
                SyncRefreshPresent::class,
                2,
                $type,
                $context,
            ),
            3 => $this->syncIdSet(
                $type,
                $context,
            ),
            default => throw new ProtocolException(sprintf(
                'The tag number %s for a SyncInfoMessage was unexpected.',
                $choice->getTagNumber(),
            )),
        };
    }

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    private function newCookie(
        AbstractType $type,
        DecodeContext $context,
    ): SyncNewCookie {
        return new SyncNewCookie(self::stringOf(
            $this->valueOf(
                $type,
                $context,
                [AbstractType::TAG_CLASS_CONTEXT_SPECIFIC => [0 => AbstractType::TAG_TYPE_OCTET_STRING]],
            ),
            'The syncCookie must be an octet string.',
        ));
    }

    /**
     * @param class-string<SyncRefreshDelete|SyncRefreshPresent> $messageClass
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    private function refreshDone(
        string $messageClass,
        int $valueTag,
        AbstractType $type,
        DecodeContext $context,
    ): SyncRefreshDelete|SyncRefreshPresent {
        // The name is only checked for its form, as each refresh message always has.
        $this->responseName($type);

        $value = $this->sequenceValueOf(
            $type,
            $context,
            $valueTag,
        );

        $cookie = null;
        $refreshDone = true;
        foreach ($value->getChildren() as $child) {
            if ($child instanceof OctetStringType) {
                $cookie = $child->getValue();
            } elseif ($child instanceof BooleanType) {
                $refreshDone = $child->getValue();
            } else {
                throw new ProtocolException('Unexpected value in the refreshPresent response.');
            }
        }

        return new $messageClass(
            $refreshDone,
            $cookie,
        );
    }

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    private function syncIdSet(
        AbstractType $type,
        DecodeContext $context,
    ): SyncIdSet {
        $this->requireSyncInfoName($type);
        $value = $this->sequenceValueOf(
            $type,
            $context,
            3,
        );

        $cookie = null;
        $refreshDeletes = false;
        $entryUuids = null;
        foreach ($value->getChildren() as $child) {
            if ($child instanceof OctetStringType) {
                $cookie = $child->getValue();
            } elseif ($child instanceof BooleanType) {
                $refreshDeletes = $child->getValue();
            } elseif ($child instanceof SetType) {
                $entryUuids = $this->entryUuidsIn($child);
            } else {
                throw new ProtocolException('Unexpected value in the syncIdSet response.');
            }
        }
        if ($entryUuids === null) {
            throw new ProtocolException('Expected a set of entryUuids, but received none.');
        }

        return new SyncIdSet(
            $entryUuids,
            $refreshDeletes,
            $cookie,
        );
    }

    /**
     * @return list<string>
     * @throws ProtocolException
     */
    private function entryUuidsIn(SetType $set): array
    {
        $entryUuids = [];
        foreach ($set->getChildren() as $entryUuid) {
            $entryUuids[] = self::stringOf(
                $entryUuid,
                'The entryUuid needs to be an octet string type.',
            );
        }

        return $entryUuids;
    }

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    private function sequenceValueOf(
        AbstractType $type,
        DecodeContext $context,
        int $valueTag,
    ): SequenceType {
        $value = $this->valueOf(
            $type,
            $context,
            [AbstractType::TAG_CLASS_CONTEXT_SPECIFIC => [$valueTag => AbstractType::TAG_TYPE_SEQUENCE]],
        );
        if (!$value instanceof SequenceType || count($type->getChildren()) >= 3) {
            throw new ProtocolException(self::MALFORMED_SEQUENCE);
        }

        return $value;
    }

    /**
     * @param AbstractType<mixed> $type
     * @param array<int, array<int, int>> $tagMap
     * @return AbstractType<mixed>
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     */
    private function valueOf(
        AbstractType $type,
        DecodeContext $context,
        array $tagMap = [],
    ): AbstractType {
        $field = $type->getChild(1);
        $rawValue = $field?->getValue();
        if (!$this->isContextField($field, 1) || !is_string($rawValue)) {
            throw new ProtocolException(self::MALFORMED_VALUE);
        }

        return $context->decode(
            $rawValue,
            $tagMap,
        );
    }

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    private function requireSyncInfoName(AbstractType $type): void
    {
        $responseName = $this->responseName($type);
        if ($responseName !== IntermediateResponse::OID_SYNC_INFO) {
            throw new ProtocolException(sprintf(
                'The response name should be "%s", but was "%s".',
                IntermediateResponse::OID_SYNC_INFO,
                $responseName,
            ));
        }
    }

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    private function responseName(AbstractType $type): string
    {
        $field = $type->getChild(0);
        $rawValue = $field?->getValue();
        if (!$this->isContextField($field, 0) || !is_string($rawValue)) {
            throw new ProtocolException(self::MALFORMED_NAME);
        }

        return $rawValue;
    }

    /**
     * @param AbstractType<mixed>|null $field
     */
    private function isContextField(
        ?AbstractType $field,
        int $tagNumber,
    ): bool {
        return $field !== null
            && $field->getTagNumber() === $tagNumber
            && $field->getTagClass() === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC;
    }
}
