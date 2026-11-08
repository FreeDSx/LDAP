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

namespace FreeDSx\Ldap\Protocol\Decoder\Request;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Asn1\Type\SetType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\OperationDecoderInterface;

use function count;
use function is_int;

/**
 * Decodes a modify request (RFC 4511 4.6).
 *
 * @implements OperationDecoderInterface<ModifyRequest>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ModifyRequestDecoder implements OperationDecoderInterface
{
    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): ModifyRequest {
        if (!($type instanceof SequenceType && count($type) >= 2)) {
            throw new ProtocolException('The modify request is malformed');
        }

        $dn = $type->getChild(0);
        $changes = $type->getChild(1);
        if (!($dn instanceof OctetStringType && $changes instanceof SequenceType)) {
            throw new ProtocolException('The modify request is malformed');
        }

        $changeList = [];
        foreach ($changes->getChildren() as $change) {
            $changeList[] = $this->change($change);
        }

        return new ModifyRequest(
            $dn->getValue(),
            ...$changeList,
        );
    }

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    private function change(AbstractType $type): Change
    {
        if (!($type instanceof SequenceType && count($type->getChildren()) >= 2)) {
            throw new ProtocolException('The change for the modify request is malformed.');
        }

        $operation = $type->getChild(0);
        $modification = $type->getChild(1);
        if (!($operation instanceof EnumeratedType && $modification instanceof SequenceType)) {
            throw new ProtocolException('The change for the modify request is malformed.');
        }

        $modType = $operation->getValue();
        if (!is_int($modType)) {
            throw new ProtocolException('The change operation type is not an integer.');
        }

        return new Change(
            $modType,
            $this->partialAttribute($modification),
        );
    }

    /**
     * @throws ProtocolException
     */
    private function partialAttribute(SequenceType $type): Attribute
    {
        if (count($type->getChildren()) < 2) {
            throw new ProtocolException('The partial attribute for the modify request is malformed.');
        }

        $attrType = $type->getChild(0);
        $attrVals = $type->getChild(1);
        if (!($attrType instanceof OctetStringType && $attrVals instanceof SetType)) {
            throw new ProtocolException('The partial attribute for the modify request is malformed.');
        }

        $values = [];
        foreach ($attrVals->getChildren() as $attrVal) {
            if (!$attrVal instanceof OctetStringType) {
                throw new ProtocolException('The partial attribute for the modify request is malformed.');
            }
            $values[] = $attrVal->getValue();
        }

        return new Attribute(
            $attrType->getValue(),
            ...$values,
        );
    }
}
