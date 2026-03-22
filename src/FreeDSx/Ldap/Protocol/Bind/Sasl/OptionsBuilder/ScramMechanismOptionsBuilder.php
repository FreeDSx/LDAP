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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface;
use FreeDSx\Sasl\Mechanism\ScramMechanism;

/**
 * Builds options for SCRAM SASL mechanisms on the server side.
 *
 * SCRAM is client-initiated: the client sends its username in the client-first-message.
 * This builder is stateful — it extracts and stores the username from the client-first
 * round so it can look up the password for the client-final round.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ScramMechanismOptionsBuilder implements MechanismOptionsBuilderInterface
{
    use RequiresPasswordTrait;

    private ?string $username = null;

    public function __construct(private readonly SaslHandlerInterface $handler)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function buildOptions(?string $received, string $mechanism): array
    {
        if ($received === null) {
            return [];
        }

        // Client-final-message contains the proof field 'p='.
        // At this point we need the password to verify the client's proof.
        if (str_contains($received, ',p=')) {
            if ($this->username === null) {
                throw new OperationException(
                    'Received a SCRAM client-final-message before client-first-message.',
                    ResultCode::PROTOCOL_ERROR
                );
            }

            return [
                'password' => $this->requirePassword(
                    $this->handler->getPassword($this->username, $mechanism)
                ),
            ];
        }

        // Client-first-message: extract and store the username for the next round.
        $this->username = $this->parseUsername($received);

        return [];
    }

    /**
     * {@inheritDoc}
     */
    public function supports(string $mechanism): bool
    {
        return in_array($mechanism, ScramMechanism::VARIANTS, true);
    }

    /**
     * Extracts the username from a SCRAM client-first-message.
     *
     * The client-first-message format is: <gs2-header> <client-first-bare>
     * where gs2-header ends with ',,' and client-first-bare contains 'n=<username>,r=<nonce>'.
     *
     * @throws OperationException if no username can be found.
     */
    private function parseUsername(string $clientFirst): string
    {
        // Strip the GS2 header (everything up to and including ',,').
        $pos = strpos($clientFirst, ',,');
        $bare = $pos !== false ? substr($clientFirst, $pos + 2) : $clientFirst;

        // Extract the 'n=' field. RFC 5802: ',' and '=' are encoded as '=2C' and '=3D'.
        if (preg_match('/(?:^|,)n=([^,]*)/', $bare, $m)) {
            return str_replace(['=2C', '=3D'], [',', '='], $m[1]);
        }

        throw new OperationException(
            'The SCRAM client-first-message did not contain a username.',
            ResultCode::PROTOCOL_ERROR
        );
    }
}
