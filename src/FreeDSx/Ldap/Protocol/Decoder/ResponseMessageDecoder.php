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

use Closure;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Response;
use FreeDSx\Ldap\Operation\Response\ResponseInterface;
use FreeDSx\Ldap\Protocol\Decoder\Control\ControlDecoderInterface;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;

/**
 * Decodes each message a server sends into the response it carries and its controls.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ResponseMessageDecoder
{
    public function __construct(
        private MessageEnvelopeReader $envelopes,
        private DecodeContextFactory $contexts,
        private ControlDecoderInterface $controls,
    ) {}

    /**
     * @param AbstractType<mixed> $pdu
     * @throws ProtocolException when the envelope cannot be read, which ends the session.
     * @throws MessageDecodeException when anything past the envelope fails, which names the message ID.
     */
    public function decode(AbstractType $pdu): LdapMessageResponse
    {
        $envelope = $this->envelopes->read($pdu);
        // Resolved before anything is decoded, so an unrecognized operation ends the session (RFC 4511 4.1.1).
        $operation = $this->operationFor($envelope);
        $context = $this->contexts->create();

        [$response, $controls] = $this->envelopes->answerable(
            $envelope,
            fn(): array => [
                $operation($envelope->operation),
                $this->envelopes->controlsOf(
                    $envelope,
                    $context,
                    $this->controls,
                ),
            ],
        );

        return new LdapMessageResponse(
            $envelope->messageId,
            $response,
            ...$controls,
        );
    }

    /**
     * @return Closure(AbstractType<mixed>): ResponseInterface
     * @throws ProtocolException
     */
    private function operationFor(MessageEnvelope $envelope): Closure
    {
        return match ($envelope->operationTag) {
            1 => Response\BindResponse::fromAsn1(...),
            4 => Response\SearchResultEntry::fromAsn1(...),
            5 => Response\SearchResultDone::fromAsn1(...),
            7 => Response\ModifyResponse::fromAsn1(...),
            9 => Response\AddResponse::fromAsn1(...),
            11 => Response\DeleteResponse::fromAsn1(...),
            13 => Response\ModifyDnResponse::fromAsn1(...),
            15 => Response\CompareResponse::fromAsn1(...),
            19 => Response\SearchResultReference::fromAsn1(...),
            24 => Response\ExtendedResponse::fromAsn1(...),
            25 => Response\IntermediateResponse::fromAsn1(...),
            default => throw $this->envelopes->unsupported($envelope->operationTag),
        };
    }
}
