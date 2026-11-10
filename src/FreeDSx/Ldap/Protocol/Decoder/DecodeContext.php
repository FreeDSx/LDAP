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
use function strlen;

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
     * The element cap the encoder holds, or null when it has none.
     */
    private ?int $cap = null;

    /**
     * @param int|null $elementsLeft the elements the nested parts may hold, or null for no limit.
     */
    public function __construct(private ?int $elementsLeft = null)
    {
        $this->encoder = new LdapEncoder();
    }

    /**
     * @param array<int, array<int, int>> $tagMap
     * @param int|null $atMost the most elements the type may hold, where 0 still allows one, or null for no limit.
     * @return AbstractType<mixed>
     * @throws EncoderException
     * @throws PduElementsException when the type holds more elements than asked for before the budget runs out.
     * @throws AdminLimitExceededException when the nested parts hold more elements than the budget.
     */
    public function complete(
        IncompleteType $type,
        int $tagType,
        array $tagMap = [],
        ?int $atMost = null,
    ): AbstractType {
        $this->capAt(
            $atMost,
            strlen($type->getValue()),
        );

        try {
            $completed = $this->encoder->complete(
                $type,
                $tagType,
                $tagMap,
            );
        } catch (PduElementsException $e) {
            throw $this->budgetCaps($atMost)
                ? $this->overBudget($e)
                : $e;
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
        $this->capAt(
            null,
            strlen($bytes),
        );

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

    /**
     * Caps the encoder at the lower of the budget left and the elements asked for, when the part could hold more.
     */
    private function capAt(
        ?int $atMost,
        int $byteLength,
    ): void {
        $cap = $this->elementsLeft;
        if ($atMost !== null && ($cap === null || $atMost <= $cap)) {
            $cap = $atMost;
        }
        // A part holds at most one element for every two bytes, and needs no cap that covers that many.
        if ($cap !== null && $cap * 2 >= $byteLength) {
            $cap = null;
        }
        if ($cap === $this->cap) {
            return;
        }
        $this->cap = $cap;

        // A cap of 0 allows one element because the encoder reads 0 as unlimited; a spent budget's charge refuses it.
        $maxElements = $cap === null
            ? 0
            : max(
                1,
                $cap,
            );
        $this->encoder->setOptions(new EncoderOptions(maxElements: $maxElements));
    }

    private function budgetCaps(?int $atMost): bool
    {
        return $this->elementsLeft !== null
            && ($atMost === null || $this->elementsLeft < $atMost);
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
