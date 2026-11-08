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

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Ad\DirSyncResponseControl;
use FreeDSx\Ldap\Control\AssertionControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Control\ProxyAuthorizationControl;
use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Control\SubentriesControl;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Request\RequestDecoderInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;

/**
 * Decodes each message a client sends into the request it carries and its controls.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class RequestMessageDecoder
{
    /**
     * @param array<int, RequestDecoderInterface> $operations the decoder of each request, keyed by its protocolOp tag.
     */
    public function __construct(
        private MessageEnvelopeReader $envelopes,
        private DecodeContextFactory $contexts,
        private array $operations,
    ) {}

    /**
     * @param AbstractType<mixed> $pdu
     * @throws ProtocolException when the envelope cannot be read, which ends the session.
     * @throws MessageDecodeException when anything past the envelope fails, which is answered by the message ID.
     */
    public function decode(AbstractType $pdu): LdapMessageRequest
    {
        $envelope = $this->envelopes->read($pdu);
        // Resolved before anything is decoded, so an unrecognized operation ends the session (RFC 4511 4.1.1).
        $operation = $this->operations[$envelope->operationTag]
            ?? throw $this->envelopes->unsupported($envelope->operationTag);
        $context = $this->contexts->create();

        [$request, $controls] = $this->envelopes->answerable(
            $envelope,
            fn(): array => [
                $operation->decode(
                    $envelope->operation,
                    $context,
                ),
                $this->envelopes->controlsOf(
                    $envelope,
                    $context,
                    $this->control(...),
                ),
            ],
        );

        return new LdapMessageRequest(
            $envelope->messageId,
            $request,
            ...$controls,
        );
    }

    private function control(SequenceType $control): Control
    {
        return match ($control->getChild(0)?->getValue()) {
            Control::OID_PAGING => PagingControl::fromAsn1($control),
            Control::OID_SORTING => SortingControl::fromAsn1($control),
            Control::OID_SORTING_RESPONSE => SortingResponseControl::fromAsn1($control),
            Control::OID_VLV_RESPONSE => VlvResponseControl::fromAsn1($control),
            Control::OID_DIR_SYNC => DirSyncResponseControl::fromAsn1($control),
            Control::OID_SYNC_STATE => SyncStateControl::fromAsn1($control),
            Control::OID_SYNC_REQUEST => SyncRequestControl::fromAsn1($control),
            Control::OID_SYNC_DONE => SyncDoneControl::fromAsn1($control),
            Control::OID_PROXY_AUTHORIZATION => ProxyAuthorizationControl::fromAsn1($control),
            Control::OID_ASSERTION => AssertionControl::fromAsn1($control),
            Control::OID_PRE_READ => PreReadControl::fromAsn1($control),
            Control::OID_POST_READ => PostReadControl::fromAsn1($control),
            Control::OID_SUBENTRIES => SubentriesControl::fromAsn1($control),
            default => Control::fromAsn1($control),
        };
    }
}
