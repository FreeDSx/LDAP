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

namespace FreeDSx\Ldap\Server\Backend\Storage\Config;

use Psr\Log\LoggerInterface;

/**
 * Backs the server with a JSON file; the container picks the runner-appropriate locking strategy.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class JsonStorageConfig implements StorageConfigInterface
{
    private function __construct(
        private string $path,
        private ?LoggerInterface $logger,
    ) {}

    public static function forFile(
        string $path,
        ?LoggerInterface $logger = null,
    ): self {
        return new self(
            $path,
            $logger,
        );
    }

    public function path(): string
    {
        return $this->path;
    }

    public function logger(): ?LoggerInterface
    {
        return $this->logger;
    }

    public function type(): StorageType
    {
        return StorageType::Json;
    }
}
