<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;

/**
 * Base handler (easy access to the response factory).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
abstract class BaseServerHandler
{
    /**
     * @var ResponseFactory
     */
    protected $responseFactory;

    public function __construct(ResponseFactory $responseFactory = null)
    {
        $this->responseFactory = $responseFactory ?? new ResponseFactory();
    }
}
