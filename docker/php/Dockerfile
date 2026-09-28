# PHP-FPM image for local development.
#
# The extension list is exactly what the application requires; if one is missing
# the app fails at runtime rather than at build time, so keep this in step with
# the Requirements section of the README.
FROM php:8.3-fpm

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        libpng-dev libjpeg62-turbo-dev libfreetype6-dev libwebp-dev \
        libzip-dev libonig-dev unzip; \
    docker-php-ext-configure gd --with-jpeg --with-freetype --with-webp; \
    docker-php-ext-install -j"$(nproc)" gd mbstring mysqli pcntl zip; \
    pecl install apcu; \
    docker-php-ext-enable apcu; \
    printf 'apc.enable_cli=1\n' > /usr/local/etc/php/conf.d/apcu.ini; \
    rm -rf /var/lib/apt/lists/*

# Sessions live outside the document root, as in a real deployment.
RUN set -eux; \
    mkdir -p /var/lib/messenger/sessions; \
    chown www-data:www-data /var/lib/messenger/sessions; \
    chmod 0700 /var/lib/messenger/sessions; \
    printf 'session.save_path=/var/lib/messenger/sessions\nexpose_php=Off\ndisplay_errors=Off\nlog_errors=On\nerror_log=/proc/self/fd/2\nupload_max_filesize=50M\npost_max_size=52M\n' \
        > /usr/local/etc/php/conf.d/messenger.ini

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/messenger
