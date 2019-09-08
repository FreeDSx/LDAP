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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\RequestContext;

/**
 * Handler methods for LDAP server requests.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface RequestHandlerInterface
{
    /**
     * An add request.
     *
     * @throws OperationException
     */
    public function add(RequestContext $context, AddRequest $add): void;

    /**
     * A compare request. This should return true or false for whether the compare matches or not.
     *
     * @throws OperationException
     */
    public function compare(RequestContext $context, CompareRequest $compare): bool;

    /**
     * A delete request.
     *
     * @throws OperationException
     */
    public function delete(RequestContext $context, DeleteRequest $delete): void;

    /**
     * An extended operation request.
     *
     * @throws OperationException
     */
    public function extended(RequestContext $context, ExtendedRequest $extended): void;

    /**
     * A request to modify an entry.
     *
     * @throws OperationException
     */
    public function modify(RequestContext $context, ModifyRequest $modify): void;

    /**
     * A request to modify the DN of an entry.
     *
     * @throws OperationException
     */
    public function modifyDn(RequestContext $context, ModifyDnRequest $modifyDn): void;

    /**
     * A search request. This should return an entries collection object.
     *
     * @throws OperationException
     */
    public function search(RequestContext $context, SearchRequest $search): Entries;

    /**
     * A simple username/password bind. It should simply return true or false for whether the username and password is
     * valid. You can also throw an operations exception, which is implicitly false, and provide an additional result
     * code and diagnostics.
     *
     * @throws OperationException
     */
    public function bind(string $username, string $password): bool;
}
