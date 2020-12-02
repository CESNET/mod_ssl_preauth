Instructions for installation under Debian

```bash
apt install -y git
pushd /tmp
git clone https://github.com/CESNET/mod_ssl_preauth
cd mod_ssl_preauth
# Install depencencies for compitaion of Apache2 module.
apt install -y apache2-dev
make && make install || exit 1
popd

cat > /etc/apache2/mods-available/ssl_preauth.load << EOF
LoadModule ssl_preauth /usr/lib/apache2/modules/mod_ssl_preauth.so
EOF 

# Enable the custom module.
a2enmod ssl_preauth
systemctl restart apache2
```
