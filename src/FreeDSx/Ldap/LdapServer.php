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

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\LdifParseException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Ldif\LdifParser;
use FreeDSx\Ldap\Ldif\Loader\LdifLoaderInterface;
use FreeDSx\Ldap\Ldif\Output\LdifOutputInterface;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\BackendAwareInterface;
use FreeDSx\Ldap\Server\AccessControl\PrivilegedBypassAccessControl;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DirectoryDumper;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DumpOptions;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestReplayer;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Socket\Exception\ConnectionException;
use Generator;

/**
 * The LDAP server.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapServer
{
    private Container $container;

    private ?AccessControlInterface $accessControl = null;

    public function __construct(
        private readonly ServerOptions $options = new ServerOptions(),
        ?Container $container = null,
    ) {
        $this->container = $container ?? Container::forServer($this->options);
    }

    /**
     * Runs the LDAP server. Binds the socket and starts accepting client connections.
     *
     * @throws ConnectionException
     */
    public function run(): void
    {
        $this->init();

        $runner = $this->options->getServerRunner() ?? $this->container->get(ServerRunnerInterface::class);

        $runner->run();
    }

    /**
     * Specify a fully custom access control implementation; rare — prefer ServerOptions rules instead.
     */
    public function useAccessControl(AccessControlInterface $acl): self
    {
        $this->accessControl = $acl;

        return $this;
    }

    /**
     * Get the options currently set for the LDAP server.
     */
    public function getOptions(): ServerOptions
    {
        return $this->options;
    }

    /**
     * Bulk-loads LDIF content records into the configured storage as one atomic batch.
     *
     * Use {@see applyChanges()} instead to replay a changelog (modify/delete/rename) through the live write path.
     *
     * @param Dn $creatorDn DN recorded as creatorsName/modifiersName on imported entries; defaults to the anonymous (empty) DN.
     * @throws LdifParseException when the LDIF cannot be parsed
     * @throws RuntimeException when the LDIF contains a non-add change record
     * @throws InvalidArgumentException when the creator DN is malformed or an entry's parent is missing
     * @throws OperationException when an entry violates the schema and validation mode is strict
     */
    public function seed(
        LdifLoaderInterface $loader,
        Dn $creatorDn = new Dn(''),
    ): self {
        $backend = $this->backend();

        (new LdapImporter(
            $backend->getStorage(),
            $backend->getOperationalAttributeGenerator(),
            $backend->getSchemaValidator(),
            $creatorDn,
        ))->importEntries($this->streamSeedEntries($loader));

        return $this;
    }

    /**
     * Replays an LDIF changelog against the configured backend via the live write path.
     *
     * Use {@see seed()} instead for bulk initial provisioning of content records straight to storage.
     *
     * @throws LdifParseException when the LDIF cannot be parsed
     * @throws OperationException when a write fails (no such entry, schema violation, etc.)
     */
    public function applyChanges(LdifLoaderInterface $loader): self
    {
        $backend = $this->backend();

        (new WriteRequestReplayer($backend))
            ->apply((new LdifParser())->parse($loader));

        return $this;
    }

    /**
     * Streams the configured storage backend's entries as RFC 2849 LDIF content records to the given output.
     *
     * Symmetric with {@see seed()}: the produced LDIF re-seeds the directory verbatim, including operational
     * attributes.
     */
    public function dump(
        LdifOutputInterface $output,
        DumpOptions $options = new DumpOptions(),
    ): self {
        $backend = $this->backend();

        $output->write((new DirectoryDumper(
            $backend,
            $backend->namingContexts(),
            $this->container->get(FilterEvaluatorInterface::class),
        ))->dump($options));

        return $this;
    }

    private function init(): void
    {
        $this->requirePdoStorageForReplica();
        // Wrap once so a privileged manager token bypasses whichever policy resolved, and inject the backend into it.
        $this->options->setAccessControl($this->injectBackendIfNeeded(
            new PrivilegedBypassAccessControl($this->resolveAccessControl()),
        ));
    }

    /**
     * A replica's write-heavy apply path and cross-process password-policy state both require PDO storage.
     */
    private function requirePdoStorageForReplica(): void
    {
        $storageConfig = $this->options->getStorageConfig();

        if ($this->options->getReplicaConfig() === null || $storageConfig instanceof PdoConfig) {
            return;
        }

        throw new RuntimeException(sprintf(
            'A read-only replica requires PDO storage, but "%s" is configured.',
            $storageConfig::class,
        ));
    }

    /**
     * The assembled storage backend from the container.
     */
    private function backend(): WritableStorageBackend
    {
        return $this->container->get(WritableStorageBackend::class);
    }

    private function resolveAccessControl(): AccessControlInterface
    {
        if ($this->accessControl !== null) {
            return $this->injectBackendIfNeeded($this->accessControl);
        }

        return $this->injectBackendIfNeeded($this->options->getAccessControl());
    }

    private function injectBackendIfNeeded(AccessControlInterface $acl): AccessControlInterface
    {
        if ($acl instanceof BackendAwareInterface) {
            $acl->setBackend($this->backend());
        }

        return $acl;
    }

    /**
     * @return Generator<Entry>
     * @throws RuntimeException when the LDIF contains a non-add change record
     * @throws LdifParseException
     */
    private function streamSeedEntries(LdifLoaderInterface $loader): Generator
    {
        foreach ((new LdifParser())->parse($loader) as $request) {
            if (!$request instanceof AddRequest) {
                throw new RuntimeException(
                    'seed() only accepts content records (adds). Use applyChanges() for modify/delete/rename.',
                );
            }

            yield $request->getEntry();
        }
    }
}
