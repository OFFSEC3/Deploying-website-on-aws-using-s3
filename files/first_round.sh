#!/bin/bash
yum clean all
yum update -y
yum install httpd php php-mysql stress -y
cd /etc/httpd/conf || exit
cp httpd.conf httpdconfbackup.conf
cd /var/www/html || exit
echo "healthy" > healthy.html
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress
rm -rf latest.tar.gz
chmod -R 755 wp-content
chown -R apache:apache wp-content
systemctl enable httpd.service
systemctl start httpd.service
