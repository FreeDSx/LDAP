# Profiling container for the FreeDSx server.
#
# Usage (from the repo root):
#   composer profile               # one-shot: up -> bench -> sample -> SVG -> down
#   composer profile -- --keep-up  # leave the stack up after sampling
#   tests/profile/profile.sh -h    # full option list (storage, runner, cpus, ...)
#
# Manual workflow (if you want fine control):
#   docker compose -f tests/profile/docker-compose.yml up -d --build
#   docker exec freedsx-profile composer install
#   docker exec -d freedsx-profile php tests/bin/ldap-backend-storage.php tcp --storage=sqlite --runner=pcntl --port=10389
#   docker exec freedsx-profile bash tests/profile/attach-phpspy.sh

FROM php:8.5-cli

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        build-essential \
        autoconf \
        pkg-config \
        unzip \
        wget \
        libsqlite3-dev \
        libssl-dev \
        libbrotli-dev \
        libcurl4-openssl-dev \
        procps \
    && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install pcntl pdo_sqlite pdo_mysql

RUN pecl install swoole \
    && docker-php-ext-enable swoole

RUN git clone --depth 1 https://github.com/adsr/phpspy.git /opt/phpspy \
    && cd /opt/phpspy \
    && make \
    && install -m 0755 phpspy /usr/local/bin/phpspy \
    && install -m 0755 stackcollapse-phpspy.pl /usr/local/bin/stackcollapse-phpspy.pl

RUN wget -q -O /usr/local/bin/flamegraph.pl \
        https://raw.githubusercontent.com/brendangregg/FlameGraph/master/flamegraph.pl \
    && chmod +x /usr/local/bin/flamegraph.pl

RUN wget -qO /usr/local/bin/composer https://getcomposer.org/composer-stable.phar \
    && chmod +x /usr/local/bin/composer

COPY php.ini /usr/local/etc/php/conf.d/zz-bench.ini

WORKDIR /app
EXPOSE 10389

CMD ["bash"]
