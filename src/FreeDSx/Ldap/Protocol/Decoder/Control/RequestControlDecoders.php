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

namespace FreeDSx\Ldap\Protocol\Decoder\Control;

use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Server\Middleware\ServerControlRegistry;

use function array_flip;
use function array_intersect_key;

/**
 * Decodes a request's controls, typing only the ones its operation takes and leaving the rest generic.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class RequestControlDecoders
{
    /**
     * @var array<class-string<RequestInterface>, ControlDecoder>
     */
    private array $byOperation = [];

    /**
     * @param array<string, ControlDecoderInterface> $typed the decoder of each typed control, keyed by its OID.
     */
    public function __construct(
        private readonly array $typed,
        private readonly ServerControlRegistry $registry,
    ) {}

    public function for(RequestInterface $request): ControlDecoder
    {
        // Keyed by class, as the operation alone decides which controls it takes.
        return $this->byOperation[$request::class] ??= new ControlDecoder(array_intersect_key(
            $this->typed,
            array_flip($this->registry->controlsTakenBy($request)),
        ));
    }
}
