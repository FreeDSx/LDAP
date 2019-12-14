<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\Queue\MessageWrapper;

use FreeDSx\Ldap\Protocol\Queue\MessageWrapperInterface;
use FreeDSx\Sasl\Exception\SaslBufferException;
use FreeDSx\Sasl\SaslBuffer;
use FreeDSx\Sasl\SaslContext;
use FreeDSx\Sasl\Security\SecurityLayerInterface;
use FreeDSx\Socket\Exception\PartialMessageException;
use FreeDSx\Socket\Queue\Buffer;
use function strlen;

/**
 * Used to wrap / unwrap SASL messages in the queue.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SaslMessageWrapper implements MessageWrapperInterface
{
    /**
     * @var SaslContext
     */
    protected $context;

    /**
     * @var SecurityLayerInterface
     */
    protected $securityLayer;

    public function __construct(SecurityLayerInterface $securityLayer, SaslContext $context)
    {
        $this->securityLayer = $securityLayer;
        $this->context = $context;
    }

    /**
     * {@inheritDoc}
     */
    public function wrap(string $message): string
    {
        $data = $this->securityLayer->wrap($message, $this->context);

        return SaslBuffer::wrap($data);
    }

    /**
     * {@inheritDoc}
     */
    public function unwrap(string $message): Buffer
    {
        try {
            $data = SaslBuffer::unwrap($message);

            return new Buffer(
                $this->securityLayer->unwrap($data, $this->context),
                strlen($data) + 4
            );
        } catch (SaslBufferException $exception) {
            throw new PartialMessageException($exception->getMessage(), $exception->getCode(), $exception);
        }
    }
}
