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
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\RequestContext;

/**
 * Request Handlers wanting more control over the RootDSE may implement this interface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface RootDseHandlerInterface
{
    /**
     * Either return your own RootDse, or just pass back / modify the entry already generated.
     *
     * @param RequestContext $context
     * @param SearchRequest $request
     * @param Entry $rootDse
     * @return Entry
     */
    public function rootDse(RequestContext $context, SearchRequest $request, Entry $rootDse): Entry;
}
