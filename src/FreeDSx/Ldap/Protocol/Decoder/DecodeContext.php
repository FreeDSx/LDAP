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

namespace FreeDSx\Ldap\Protocol\Decoder;

use FreeDSx\Asn1\Encoder\EncoderOptions;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Exception\PduElementsException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Exception\AdminLimitExceededException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;

use function max;

/**
 * Decodes the nested parts of one received message, all through the same encoder and within one element budget.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DecodeContext
{
    private readonly LdapEncoder $encoder;

    /**
     * @param int|null $elementsLeft the elements the nested parts may hold, or null for no limit.
     */
    public function __construct(private ?int $elementsLeft = null)
    {
        $this->encoder = new LdapEncoder();
    }

    /**
     * @param array<int, array<int, int>> $tagMap
     * @return AbstractType<mixed>
     * @throws EncoderException
     * @throws AdminLimitExceededException when the nested parts hold more elements than the budget.
     */
    public function complete(
        IncompleteType $type,
        int $tagType,
        array $tagMap = [],
    ): AbstractType {
        $this->applyBudget();

        try {
            $completed = $this->encoder->complete(
                $type,
                $tagType,
                $tagMap,
            );
        } catch (PduElementsException $e) {
            throw $this->overBudget($e);
        }
        $this->charge();

        return $completed;
    }

    /**
     * @param array<int, array<int, int>> $tagMap
     * @return AbstractType<mixed>
     * @throws EncoderException
     * @throws PartialPduException
     * @throws ProtocolException when the bytes are empty.
     * @throws AdminLimitExceededException when the nested parts hold more elements than the budget.
     */
    public function decode(
        string $bytes,
        array $tagMap = [],
    ): AbstractType {
        // An empty value is answered as malformed rather than ending the session.
        if ($bytes === '') {
            throw new ProtocolException('The data to decode cannot be empty.');
        }
        $this->applyBudget();

        try {
            $decoded = $this->encoder->decode(
                $bytes,
                $tagMap,
            );
        } catch (PduElementsException $e) {
            throw $this->overBudget($e);
        }
        $this->charge();

        return $decoded;
    }

    private function applyBudget(): void
    {
        if ($this->elementsLeft === null) {
            return;
        }

        // A spent budget still allows one element because the encoder reads 0 as unlimited; the charge refuses it.
        $this->encoder->setOptions(new EncoderOptions(maxElements: max(
            1,
            $this->elementsLeft,
        )));
    }

    /**
     * @throws AdminLimitExceededException
     */
    private function charge(): void
    {
        if ($this->elementsLeft === null) {
            return;
        }
        $this->elementsLeft -= $this->encoder->getLastElementCount();

        if ($this->elementsLeft < 0) {
            throw $this->overBudget();
        }
    }

    private function overBudget(?PduElementsException $previous = null): AdminLimitExceededException
    {
        return new AdminLimitExceededException(
            'The request holds more elements than the server allows.',
            $previous,
        );
    }
}
