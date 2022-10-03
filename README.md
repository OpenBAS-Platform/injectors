# OpenEx injectors

The following repository is used to store the OpenEx injectors for the platform integration with other tools and applications.

## OpenEx usage

Injectors must be started along with the platform api, using "lib" directory
- openex-api.jar
- lib/openex-injector-01.jar 
- lib/openex-injector-02.jar
- lib/openex-injector-03.jar

> java -Dloader.path=file:lib/ -jar openex-api.jar

## Contributing

If you want to help use improve or develop new injector, please check out the **[development documentation for new injectors](https://filigran.notion.site/Injector-Development-5752d0dbe56d4e86937a7eda0b4610d9)**. If you want to make your connector available to the community, **please create a Pull Request on this repository**, then we will integrate it to the CI and in the [OpenEx ecosystem](https://filigran.notion.site/OpenEx-Ecosystem-30d8eb73d7d04611843e758ddef8941b).

## License

**Unless specified otherwise**, connectors are released under the [Apache 2.0](https://github.com/OpenEX-Platform/injectors/blob/master/LICENSE). If a connector is released by its author under a different license, the subfolder corresponding to it will contain a *LICENSE* file.

## About

OpenEx is a product powered by the collaboration of the private company [Filigran](https://www.filigran.io), the [French national cybersecurity agency (ANSSI)](https://ssi.gouv.fr), the [CERT-EU](https://cert.europa.eu) and the [Luatix](https://www.luatix.org) non-profit organization.