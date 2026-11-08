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

namespace FreeDSx\Ldap\Container\Provider;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\Decoder\Control\AssertionControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\ControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\DirSyncResponseControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\PagingControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\ProxyAuthorizationControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\PwdPolicyResponseControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\ReadEntryControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\ReadEntryResponseControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\SortingControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\SortingResponseControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\SubentriesControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\SubtreeDeleteProgressControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\SyncDoneControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\SyncRequestControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\SyncStateControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\VlvResponseControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\MessageEnvelopeReader;
use FreeDSx\Ldap\Protocol\Decoder\Request\AbandonRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\AddRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\BindRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\CancelRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\CompareRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\DeleteRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\ExtendedRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\ForwardPasswordPolicyStateRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\ModifyDnRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\ModifyRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\PasswordModifyRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\SearchRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\UnbindRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\Decoder\ResponseMessageDecoder;
use FreeDSx\Ldap\Schema\Validation\Syntax\UuidSyntaxValidator;

/**
 * Registers the decoders that turn received messages into requests and responses.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DecoderContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            DecodeContextFactory::class => $this->makeDecodeContextFactory(...),
            MessageEnvelopeReader::class => $this->makeMessageEnvelopeReader(...),
            RequestMessageDecoder::class => $this->makeRequestMessageDecoder(...),
            ResponseMessageDecoder::class => $this->makeResponseMessageDecoder(...),
            AbandonRequestDecoder::class => static fn(): AbandonRequestDecoder => new AbandonRequestDecoder(),
            AddRequestDecoder::class => static fn(): AddRequestDecoder => new AddRequestDecoder(),
            BindRequestDecoder::class => static fn(): BindRequestDecoder => new BindRequestDecoder(),
            CompareRequestDecoder::class => static fn(): CompareRequestDecoder => new CompareRequestDecoder(),
            DeleteRequestDecoder::class => static fn(): DeleteRequestDecoder => new DeleteRequestDecoder(),
            ModifyDnRequestDecoder::class => static fn(): ModifyDnRequestDecoder => new ModifyDnRequestDecoder(),
            ModifyRequestDecoder::class => static fn(): ModifyRequestDecoder => new ModifyRequestDecoder(),
            SearchRequestDecoder::class => static fn(): SearchRequestDecoder => new SearchRequestDecoder(),
            UnbindRequestDecoder::class => static fn(): UnbindRequestDecoder => new UnbindRequestDecoder(),
            ExtendedRequestDecoder::class => $this->makeExtendedRequestDecoder(...),
            CancelRequestDecoder::class => static fn(): CancelRequestDecoder => new CancelRequestDecoder(),
            ForwardPasswordPolicyStateRequestDecoder::class => $this->makeForwardPasswordPolicyStateRequestDecoder(...),
            PasswordModifyRequestDecoder::class => static fn(): PasswordModifyRequestDecoder
                => new PasswordModifyRequestDecoder(),
            AssertionControlDecoder::class => static fn(): AssertionControlDecoder => new AssertionControlDecoder(),
            DirSyncResponseControlDecoder::class => static fn(): DirSyncResponseControlDecoder
                => new DirSyncResponseControlDecoder(),
            PagingControlDecoder::class => static fn(): PagingControlDecoder => new PagingControlDecoder(),
            ProxyAuthorizationControlDecoder::class => static fn(): ProxyAuthorizationControlDecoder
                => new ProxyAuthorizationControlDecoder(),
            PwdPolicyResponseControlDecoder::class => static fn(): PwdPolicyResponseControlDecoder
                => new PwdPolicyResponseControlDecoder(),
            SortingControlDecoder::class => static fn(): SortingControlDecoder => new SortingControlDecoder(),
            SortingResponseControlDecoder::class => static fn(): SortingResponseControlDecoder
                => new SortingResponseControlDecoder(),
            SubentriesControlDecoder::class => static fn(): SubentriesControlDecoder
                => new SubentriesControlDecoder(),
            SubtreeDeleteProgressControlDecoder::class => static fn(): SubtreeDeleteProgressControlDecoder
                => new SubtreeDeleteProgressControlDecoder(),
            SyncDoneControlDecoder::class => static fn(): SyncDoneControlDecoder => new SyncDoneControlDecoder(),
            SyncRequestControlDecoder::class => static fn(): SyncRequestControlDecoder
                => new SyncRequestControlDecoder(),
            SyncStateControlDecoder::class => static fn(): SyncStateControlDecoder => new SyncStateControlDecoder(),
            VlvResponseControlDecoder::class => static fn(): VlvResponseControlDecoder
                => new VlvResponseControlDecoder(),
        ];
    }

    private function makeExtendedRequestDecoder(Container $container): ExtendedRequestDecoder
    {
        return new ExtendedRequestDecoder([
            ExtendedRequest::OID_CANCEL => $container->get(CancelRequestDecoder::class),
            ExtendedRequest::OID_PPOLICY_STATE_FORWARD => $container->get(
                ForwardPasswordPolicyStateRequestDecoder::class,
            ),
        ]);
    }

    private function makeForwardPasswordPolicyStateRequestDecoder(): ForwardPasswordPolicyStateRequestDecoder
    {
        return new ForwardPasswordPolicyStateRequestDecoder(new UuidSyntaxValidator());
    }

    private function makeDecodeContextFactory(): DecodeContextFactory
    {
        return new DecodeContextFactory();
    }

    private function makeMessageEnvelopeReader(): MessageEnvelopeReader
    {
        return new MessageEnvelopeReader();
    }

    private function makeRequestMessageDecoder(Container $container): RequestMessageDecoder
    {
        // Keyed by the protocolOp tag RFC 4511 4.2 to 4.12 assigns each request.
        return new RequestMessageDecoder(
            $container->get(MessageEnvelopeReader::class),
            $container->get(DecodeContextFactory::class),
            [
                0 => $container->get(BindRequestDecoder::class),
                2 => $container->get(UnbindRequestDecoder::class),
                3 => $container->get(SearchRequestDecoder::class),
                6 => $container->get(ModifyRequestDecoder::class),
                8 => $container->get(AddRequestDecoder::class),
                10 => $container->get(DeleteRequestDecoder::class),
                12 => $container->get(ModifyDnRequestDecoder::class),
                14 => $container->get(CompareRequestDecoder::class),
                16 => $container->get(AbandonRequestDecoder::class),
                23 => $container->get(ExtendedRequestDecoder::class),
            ],
            $this->makeRequestControlDecoder($container),
        );
    }

    private function makeResponseMessageDecoder(Container $container): ResponseMessageDecoder
    {
        return new ResponseMessageDecoder(
            $container->get(MessageEnvelopeReader::class),
            $container->get(DecodeContextFactory::class),
            $this->makeResponseControlDecoder($container),
        );
    }

    private function makeRequestControlDecoder(Container $container): ControlDecoder
    {
        return new ControlDecoder([
            Control::OID_PAGING => $container->get(PagingControlDecoder::class),
            Control::OID_SORTING => $container->get(SortingControlDecoder::class),
            Control::OID_SORTING_RESPONSE => $container->get(SortingResponseControlDecoder::class),
            Control::OID_VLV_RESPONSE => $container->get(VlvResponseControlDecoder::class),
            Control::OID_DIR_SYNC => $container->get(DirSyncResponseControlDecoder::class),
            Control::OID_SYNC_STATE => $container->get(SyncStateControlDecoder::class),
            Control::OID_SYNC_REQUEST => $container->get(SyncRequestControlDecoder::class),
            Control::OID_SYNC_DONE => $container->get(SyncDoneControlDecoder::class),
            Control::OID_PROXY_AUTHORIZATION => $container->get(ProxyAuthorizationControlDecoder::class),
            Control::OID_ASSERTION => $container->get(AssertionControlDecoder::class),
            Control::OID_PRE_READ => new ReadEntryControlDecoder(PreReadControl::class),
            Control::OID_POST_READ => new ReadEntryControlDecoder(PostReadControl::class),
            Control::OID_SUBENTRIES => $container->get(SubentriesControlDecoder::class),
        ]);
    }

    private function makeResponseControlDecoder(Container $container): ControlDecoder
    {
        return new ControlDecoder([
            Control::OID_PWD_POLICY => $container->get(PwdPolicyResponseControlDecoder::class),
            Control::OID_PRE_READ => new ReadEntryResponseControlDecoder(PreReadResponseControl::class),
            Control::OID_POST_READ => new ReadEntryResponseControlDecoder(PostReadResponseControl::class),
            Control::OID_SUBTREE_DELETE_PROGRESS => $container->get(SubtreeDeleteProgressControlDecoder::class),
            Control::OID_PAGING => $container->get(PagingControlDecoder::class),
            Control::OID_SORTING => $container->get(SortingControlDecoder::class),
            Control::OID_SORTING_RESPONSE => $container->get(SortingResponseControlDecoder::class),
            Control::OID_VLV_RESPONSE => $container->get(VlvResponseControlDecoder::class),
            Control::OID_DIR_SYNC => $container->get(DirSyncResponseControlDecoder::class),
            Control::OID_SYNC_STATE => $container->get(SyncStateControlDecoder::class),
            Control::OID_SYNC_REQUEST => $container->get(SyncRequestControlDecoder::class),
            Control::OID_SYNC_DONE => $container->get(SyncDoneControlDecoder::class),
            Control::OID_PROXY_AUTHORIZATION => $container->get(ProxyAuthorizationControlDecoder::class),
            Control::OID_ASSERTION => $container->get(AssertionControlDecoder::class),
            Control::OID_SUBENTRIES => $container->get(SubentriesControlDecoder::class),
        ]);
    }
}
