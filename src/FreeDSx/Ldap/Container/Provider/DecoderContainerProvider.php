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
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
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
        return new RequestMessageDecoder(
            $container->get(MessageEnvelopeReader::class),
            $container->get(DecodeContextFactory::class),
        );
    }

    private function makeResponseMessageDecoder(Container $container): ResponseMessageDecoder
    {
        return new ResponseMessageDecoder(
            $container->get(MessageEnvelopeReader::class),
            $container->get(DecodeContextFactory::class),
        );
    }
}
