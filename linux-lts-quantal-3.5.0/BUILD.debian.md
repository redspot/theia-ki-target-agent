# temporary notes on building the kernel into a set of deb packages

```sh
# if needed
apt install kernel-wedge 

cd linux-lts-quantal-3.5.0
# delete or rename previous 'debian' directory
cp -r debian.theia debian
bash compile-debian
```
