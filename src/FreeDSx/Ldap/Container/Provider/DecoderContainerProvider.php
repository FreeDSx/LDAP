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
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\MessageEnvelopeReader;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\Decoder\ResponseMessageDecoder;

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
        ];
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
