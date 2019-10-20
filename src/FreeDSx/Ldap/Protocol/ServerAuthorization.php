<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Abstracts out some of the server authorization logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerAuthorization
{
    /**
     * @var bool
     */
    protected $isAuthRequired;

    /**
     * @var bool
     */
    protected $isAnonymousAllowed;

    /**
     * @var TokenInterface
     */
    protected $token;

    public function __construct(TokenInterface $token = null, array $options = [])
    {
        $this->token = $token ?? new AnonToken();
        $this->isAuthRequired = isset($options['require_authentication']) ? (bool) $options['require_authentication'] : true;
        $this->isAnonymousAllowed = isset($options['allow_anonymous']) ? (bool) $options['allow_anonymous'] : false;
    }

    /**
     * Helps determine if a specific request type actually requires authentication to complete.
     *
     * @param RequestInterface $request
     * @return bool
     */
    public function isAuthenticationRequired(RequestInterface $request): bool
    {
        if ($this->isAuthRequired === false) {
            return  false;
        }

        if ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_WHOAMI) {
            return false;
        } elseif ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_START_TLS) {
            return false;
        } elseif ($request instanceof UnbindRequest) {
            return false;
        } elseif ($request instanceof BindRequest) {
            return false;
        } elseif ($this->isRootDseSearch($request)) {
            return false;
        }

        return true;
    }

    /**
     * Determine if the bind type is actually supported. Anonymous binding may be disabled.
     */
    public function isAuthenticationTypeSupported(RequestInterface $request): bool
    {
        if ($request instanceof AnonBindRequest) {
            return $this->isAnonymousAllowed;
        }

        return $request instanceof SimpleBindRequest;
    }

    /**
     * Determine if the incoming request is an authentication attempt.
     */
    public function isAuthenticationRequest(RequestInterface $request): bool
    {
        return $request instanceof BindRequest;
    }

    /**
     * Determine if the current token is "authenticated". In the case where authentication is not required, we always
     * return true.
     */
    public function isAuthenticated(): bool
    {
        if ($this->isAuthRequired === false) {
            return true;
        }

        return $this->token instanceof BindToken;
    }

    /**
     * Set the current token.
     */
    public function setToken(TokenInterface $token): void
    {
        $this->token = $token;
    }

    /**
     * Get the current token.
     */
    public function getToken(): TokenInterface
    {
        return $this->token;
    }

    /**
     * @param RequestInterface $request
     * @return bool
     */
    protected function isRootDseSearch(RequestInterface $request): bool
    {
        if (!$request instanceof SearchRequest) {
            return false;
        }

        return $request->getScope() === SearchRequest::SCOPE_BASE_OBJECT
            && ((string) $request->getBaseDn() === '');
    }
}
