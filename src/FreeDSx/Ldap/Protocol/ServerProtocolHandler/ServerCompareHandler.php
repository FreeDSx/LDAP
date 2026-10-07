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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\AccessControl\WithheldAttributePolicy;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Operation\CompareOperationResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Answers a CompareRequest against the backend.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerCompareHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private ReadBackendInterface $backend,
        private AssertionEvaluator $assertions,
        private WithheldAttributePolicy $withheld,
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    /**
     * {@inheritDoc}
     *
     * @throws EncoderException
     * @throws OperationException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $request = $message->getRequest();

        if (!$request instanceof CompareRequest) {
            throw new RuntimeException(sprintf(
                'Expected a compare request, but got %s.',
                $request::class,
            ));
        }

        // The assertion and the comparison are answered from one read of the entry (RFC 4528 §3).
        $entry = $this->backend->getOrFail($request->getDn());
        $this->assertions->assertSatisfiedBy(
            $entry,
            $message->controls(),
            $token,
        );

        $filter = $request->getFilter();
        $match = !$this->withheld->isWithheldFromFilter($filter->getAttribute(), $token) && $this->backend->compare(
            $entry,
            $filter,
        );

        return ResponseStream::of(
            [$this->responseFactory->getStandardResponse(
                $message,
                $match
                    ? ResultCode::COMPARE_TRUE
                    : ResultCode::COMPARE_FALSE,
            )],
            CompareOperationResult::completed(
                $message,
                $match,
            ),
        );
    }
}
