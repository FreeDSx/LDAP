<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\RequestContext;

/**
 * Proxies requests to an LDAP server, including the RootDSE.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ProxyHandler extends ProxyRequestHandler implements RootDseHandlerInterface
{
    public function __construct(LdapClient $client)
    {
        $this->ldap = $client;
    }

    /**
     * @inheritDoc
     */
    public function rootDse(
        RequestContext $context,
        SearchRequest $request,
        Entry $rootDse
    ): Entry {
        $rootDse = $this->ldap()
            ->search(
                $request,
                ...$context->controls()->toArray()
            )
            ->first();

        // This technically could happen...but should not.
        if (!$rootDse) {
            throw new OperationException(
                'Entry not found.',
                ResultCode::NO_SUCH_OBJECT
            );
        }

        return $rootDse;
    }
}
