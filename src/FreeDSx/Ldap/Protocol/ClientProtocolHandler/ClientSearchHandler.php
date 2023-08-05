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

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;

/**
 * Logic for handling search operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientSearchHandler extends ClientBasicHandler
{
    use ClientSearchTrait;

    public function __construct(private readonly ClientQueue $queue)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function handleRequest(ClientProtocolContext $context): ?LdapMessageResponse
    {
        /** @var SearchRequest $request */
        $request = $context->getRequest();
        if ($request->getBaseDn() === null) {
            $request->setBaseDn($context->getOptions()->getBaseDn() ?? null);
        }

        return parent::handleRequest($context);
    }

    /**
     * {@inheritDoc}
     */
    public function handleResponse(
        LdapMessageRequest $messageTo,
        LdapMessageResponse $messageFrom,
    ): ?LdapMessageResponse {
        $finalResponse = $this->search(
            $messageFrom,
            $messageTo,
            $this->queue,
        );

        return parent::handleResponse(
            $messageTo,
            $finalResponse
        );
    }
}
