
<p align="center">
  <img alt="Jaeles" src="https://image.flaticon.com/icons/svg/1432/1432425.svg" height="140" />
  <p align="center">
    <a href=""><img alt="Software License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square"></a>
    <a href="https://github.com/jaeles-project/jaeles"><img alt="Release" src="https://img.shields.io/badge/version-beta%20v0.5-blue.svg"></a>
    <a href="https://inventory.rawsec.ml/tools.html#Jaeles"><img src="https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat.svg" alt="Rawsec&#39;s CyberSecurity Inventory"></a>
  </p>
</p>

**Jaeles** is a powerful, flexible and easily extensible framework written in Go for building your own Web Application Scanner.

![Architecture](https://github.com/jaeles-project/jaeles-plugins/blob/master/imgs/jaeles-architecture.png?raw=true)

## Installation
Download [precompiled version here](https://github.com/jaeles-project/jaeles/releases).

If you have a Go environment, make sure you have **Go >= 1.13** with Go Modules enable and run the following command.

```shell
GO111MODULE=on go get -u github.com/jaeles-project/jaeles
```

Please visit the [Official Documention](https://jaeles-project.github.io/) for more details.

**Note**: Checkout [Signature Repo](https://github.com/jaeles-project/jaeles-signatures) for base signature and passive signature.

## Usage

More usage [here](https://jaeles-project.github.io/usage/)

Example commands.

```shell
jaeles scan -s 'jira' -s 'ruby' -u target.com

jaeles scan -c 50 -s 'java' -x 'tomcat' -U list_of_urls.txt

jaeles scan -c 50 -s '/tmp/custom-signature/.*' -U list_of_urls.txt

cat urls.txt | grep 'interesting' | jaeles scan -c 50 -s 'fuzz/.*' -U list_of_urls.txt --proxy http://127.0.0.1:8080

jaeles server --verbose -s sqli
```

## Showcases

|  ![apache-status.png](https://github.com/jaeles-project/jaeles-plugins/blob/master/imgs/apache-status.png?raw=true) [**Apache Server Status**](https://youtu.be/nkBcIvzi3H4)  |  ![tableau-dom-xss.png](https://github.com/jaeles-project/jaeles-plugins/blob/master/imgs/tableau-dom-xss.png?raw=true) [**Tableau DOM XSS CVE-2019-19719**](https://youtu.be/EG7Qmt8kt58) |
|:----------:|:-------------:|
| ![rabbitmq-cred.png](https://github.com/jaeles-project/jaeles-plugins/blob/master/imgs/rabbitmq-cred.png?raw=true) [**RabbitMQ Default Credentials**](https://youtu.be/ed4n1sCNu3s) | ![jenkins-xss.png](https://github.com/jaeles-project/jaeles-plugins/blob/master/imgs/jenkins-xss.png?raw=true) [**Jenkins XSS CVE-2020-2096**](https://youtu.be/JfihhEOEWSE) |

<h4 align='center'> More showcase can be found <a href="https://jaeles-project.github.io/showcases/">here</a></h4>

### Burp Integration

![Burp Integration](https://github.com/jaeles-project/jaeles-plugins/blob/master/imgs/Burp-Integration.gif?raw=true)

Plugin can be found [here](https://github.com/jaeles-project/jaeles-plugins/blob/master/jaeles-burp.py) and Video Guide [here](https://youtu.be/1lxsYhfTq3M)

## Mentions

[My introduction slide about Jaeles](https://speakerdeck.com/j3ssie/jaeles-the-swiss-army-knife-for-automated-web-application-testing)


### Planned Features

* Adding more signatures.
* Adding more input sources.
* Adding more APIs to get access to more properties of the request.
* Adding proxy plugins to directly receive input from browser of http client.
* ~~Adding passive signature for passive checking each request.~~
* Adding more action on Web UI.
* Integrate with many other tools.

## Contribute

If you have some new idea about this project, issue, feedback or found some valuable tool feel free to open an issue for just DM me via @j3ssiejjj.
Feel free to submit new signature to this [repo](https://github.com/jaeles-project/jaeles-signatures).

### Credits

* Special thanks to [chaitin](https://github.com/chaitin/xray) team for sharing ideas to me for build the architecture.

* React components is powered by [Carbon](https://www.carbondesignsystem.com/) and [carbon-tutorial](https://github.com/carbon-design-system/carbon-tutorial).

* Awesomes artworks are powered by [Freepik](http://freepik.com) at [flaticon.com](http://flaticon.com).

## In distributions

[![Packaging status](https://repology.org/badge/vertical-allrepos/jaeles.svg)](https://repology.org/project/jaeles/versions)

## Contributors

### Code Contributors

This project exists thanks to all the people who contribute. [[Contribute](CONTRIBUTING.md)].
<a href="https://github.com/jaeles-project/jaeles/graphs/contributors"><img src="https://opencollective.com/jaeles-project/contributors.svg?width=890" /></a>

### Financial Contributors

Become a financial contributor and help us sustain our community. [[Contribute](https://opencollective.com/jaeles-project/contribute)]

#### Individuals

<a href="https://opencollective.com/jaeles-project"><img src="https://opencollective.com/jaeles-project/individuals.svg?width=890"></a>

#### Organizations

Support this project with your organization. Your logo will show up here with a link to your website. [[Contribute](https://opencollective.com/jaeles-project/contribute)]

<a href="https://opencollective.com/jaeles-project/organization/0/website"><img src="https://opencollective.com/jaeles-project/organization/0/avatar.svg"></a>
<a href="https://opencollective.com/jaeles-project/organization/1/website"><img src="https://opencollective.com/jaeles-project/organization/1/avatar.svg"></a>
<a href="https://opencollective.com/jaeles-project/organization/2/website"><img src="https://opencollective.com/jaeles-project/organization/2/avatar.svg"></a>
<a href="https://opencollective.com/jaeles-project/organization/3/website"><img src="https://opencollective.com/jaeles-project/organization/3/avatar.svg"></a>
<a href="https://opencollective.com/jaeles-project/organization/4/website"><img src="https://opencollective.com/jaeles-project/organization/4/avatar.svg"></a>
<a href="https://opencollective.com/jaeles-project/organization/5/website"><img src="https://opencollective.com/jaeles-project/organization/5/avatar.svg"></a>
<a href="https://opencollective.com/jaeles-project/organization/6/website"><img src="https://opencollective.com/jaeles-project/organization/6/avatar.svg"></a>
<a href="https://opencollective.com/jaeles-project/organization/7/website"><img src="https://opencollective.com/jaeles-project/organization/7/avatar.svg"></a>
<a href="https://opencollective.com/jaeles-project/organization/8/website"><img src="https://opencollective.com/jaeles-project/organization/8/avatar.svg"></a>
<a href="https://opencollective.com/jaeles-project/organization/9/website"><img src="https://opencollective.com/jaeles-project/organization/9/avatar.svg"></a>

## License

`Jaeles` is made with ♥  by [@j3ssiejjj](https://twitter.com/j3ssiejjj) and it is released under the MIT license.
