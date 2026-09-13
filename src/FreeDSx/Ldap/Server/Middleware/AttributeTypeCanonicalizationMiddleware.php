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

namespace FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Control\AssertionControl;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Control\ReadEntry\ReadEntryControl;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Schema\AttributeTypeSpelling;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;

use function array_map;
use function array_values;

/**
 * Spells the attribute types a request and its controls name by their primary schema names.
 *
 * RFC 4512 §2.5 lets an alias or numeric OID name a type.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AttributeTypeCanonicalizationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AttributeTypeSpelling $spelling,
    ) {}

    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $this->rewriteRequest($context->message->getRequest());
        $this->rewriteControls($context->message->controls());

        return $next->handle($context);
    }

    private function rewriteRequest(RequestInterface $request): void
    {
        match (true) {
            $request instanceof AddRequest => $request->setEntry($this->spelling->entry($request->getEntry())),
            $request instanceof ModifyRequest => $this->rewriteModify($request),
            $request instanceof ModifyDnRequest => $this->rewriteModifyDn($request),
            $request instanceof DeleteRequest => $request->setDn($this->spelling->dn($request->getDn())),
            $request instanceof CompareRequest => $this->rewriteCompare($request),
            $request instanceof SearchRequest => $this->rewriteSearch($request),
            $request instanceof SimpleBindRequest => $this->rewriteBindName($request),
            default => null,
        };
    }

    private function rewriteControls(ControlBag $controls): void
    {
        foreach ($controls->toArray() as $control) {
            match (true) {
                $control instanceof SortingControl => $this->rewriteSortKeys($control),
                $control instanceof AssertionControl => $this->spelling->rewriteFilter($control->getFilter()),
                $control instanceof ReadEntryControl => $this->replaceReadEntryControl($controls, $control),
                default => null,
            };
        }
    }

    private function rewriteModify(ModifyRequest $request): void
    {
        $request->setDn($this->spelling->dn($request->getDn()));
        $request->setChanges(...array_map(
            $this->spelling->change(...),
            $request->getChanges(),
        ));
    }

    private function rewriteModifyDn(ModifyDnRequest $request): void
    {
        $request->setDn($this->spelling->dn($request->getDn()));
        $request->setNewRdn($this->spelling->rdn($request->getNewRdn()));

        $newParent = $request->getNewParentDn();

        if ($newParent !== null) {
            $request->setNewParentDn($this->spelling->dn($newParent));
        }
    }

    private function rewriteCompare(CompareRequest $request): void
    {
        $request->setDn($this->spelling->dn($request->getDn()));
        $this->spelling->rewriteFilter($request->getFilter());
    }

    private function rewriteSearch(SearchRequest $request): void
    {
        $base = $request->getBaseDn();

        if ($base !== null) {
            $request->setBaseDn($this->spelling->dn($base));
        }

        $this->spelling->rewriteFilter($request->getFilter());
        $request->setAttributes(...array_map(
            fn(Attribute $attribute): string => $this->spelling->description($attribute->getDescription()),
            $request->getAttributes(),
        ));
    }

    /**
     * A bind name that is not a DN does not parse, so it is passed on as given for the identity resolver to read.
     */
    private function rewriteBindName(SimpleBindRequest $request): void
    {
        $name = new Dn($request->getUsername());
        $respelled = $this->spelling->dn($name);

        if ($respelled !== $name) {
            $request->setUsername($respelled->toString());
        }
    }

    private function rewriteSortKeys(SortingControl $control): void
    {
        foreach ($control->getSortKeys() as $sortKey) {
            $sortKey->setAttribute($this->spelling->description($sortKey->getAttribute()));
        }
    }

    /**
     * A read-entry control holds its attribute selection immutably, so a respelled copy takes its place.
     */
    private function replaceReadEntryControl(
        ControlBag $controls,
        ReadEntryControl $control,
    ): void {
        $attributes = array_values(array_map(
            $this->spelling->description(...),
            $control->getAttributes(),
        ));

        if ($attributes === array_values($control->getAttributes())) {
            return;
        }

        $respelled = $control instanceof PreReadControl
            ? new PreReadControl(...$attributes)
            : new PostReadControl(...$attributes);

        $controls->remove($control);
        $controls->add($respelled->setCriticality($control->getCriticality()));
    }
}
