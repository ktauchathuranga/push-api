FROM php:7.4-fpm
RUN docker-php-ext-install pdo_mysql
RUN apt-get update && apt-get install -y libcurl4-openssl-dev && docker-php-ext-install curl
WORKDIR /var/www/html