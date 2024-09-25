<!--

    Copyright 2019-Present Sonatype Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

-->
# Sonatype Lifecycle config-as-code

This project provides the capability to automate the configuration of the IQ Server, by applying configuration data
from JSON config file(s). It further supports the capability to 'scrape' existing config and persist to JSON config files
from where it can be re-applied. Additional evaluation of the configuration on IQ server is provided by a healthcheck
capability, which informs your configuration in a more human readable format. Discuss the findings with your Sonatype CSE.
The 'apply', 'healthcheck' and 'scrape' may be scoped to specific data.

This capability supports Sonatype customers aspiration to stand-up/tear-down an IQ environment in support of business
continuity and service resiliency.

Configuration is applied in 2 layers:

    1. System

    2. Organization

The conf directory contains files for individual configuration items in addition to the system-conf.json and
example-org.json that correspond with the aforementioned layers. Default data contained within the config files will
need to be modified. Please discuss this with your Sonatype CSE.


Proxy Server Note:

    If you are using a Proxy Server (A server that acts a gateway between the client and the internet) - please be aware that this project only supports the
    use of a HTTP Proxy and if it is defined within the system properties. This script will not work if a HTTPS Proxy is being used or if your Broswer is
    utilizing a .pac file

Usage

    $ python3 iq-healthcheck.py --help

    $ python3 iq-scrape-conf.py --help

    $ python3 iq-apply-conf.py --help

Docker Usage

    Build the image by your own:

        $ docker build -t sonatypecommunity/iq-config-as-code:latest .

    Build the image by your own with a custom base image:

        $ docker build -t sonatypecommunity/iq-config-as-code:latest --build-arg BASEIMAGE=python:3.9.6-alpine3.14 .

    In case you need some custom user ids or group ids, you could just build the image with those args:

        $ docker build -t sonatypecommunity/iq-config-as-code:latest --build-arg USER_ID=1001 --build-arg GROUP_ID=1001 .

    Run with local image:

        docker run --rm -i -v $PWD:/data sonatypecommunity/iq-config-as-code:latest <iq-script>

    Run with the latest upstream image:

        docker run --rm -i -v $PWD:/data sonatypecommunity/iq-config-as-code:latest <iq-script>

Usage: iq-scrape-config [ARGS]...

  Example usage:

    # Run python script though docker container with all packages installed on it!
    docker run --rm -i -v $PWD:/data sonatypecommunity/iq-config-as-code:latest iq-scrape-conf -u "http://<iq-hostname>:<iq-port>" -a <user>:<password>

    # Run the script natively on your host
    python3 iq-scrape-conf.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp

    # Scrape specific organisation
    python3 iq-scrape-conf.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp -y "My Org"

    # Scrape specific application public-id
    # The application public-id is id by which you identify an application when scanning with the cli.
    python3 iq-scrape-conf.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp -y "application-x"

    # Scrape specific organisation(s) and specific application(s) public-id(s)
    python3 iq-scrape-conf.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp -y "My Org,Your Org,application-x,application-y"


Usage: iq-apply-config [ARGS]...

  Example usage:

    # Run python script though docker container with all packages installed on it!
    docker run --rm -i -v $PWD:/data sonatypecommunity/iq-config-as-code:latest iq-apply-conf -f /data/scrape/<conf-file>.json -u http://<iq-hostname>:<iq-port> -a <user>:<password>

    # Run the script natively on your host
    python3 iq-apply-conf.py -f conf/<conf-file>.json -a <user>:<password> -u <protocol>://<hostname>:<port>

    python3 iq-apply-conf.py -f scrape/System-Config.json  -a <user>:<password> -u <protocol>://<hostname>:<port> -s True

    python3 iq-apply-conf.py -f scrape/All-Organizations-Config.json  -a <user>:<password> -u <protocol>://<hostname>:<port>

    The iq-apply-config script will not override configuration pertaining to child organizations and applications. It will override 'Root' organization
    configuration! It imports the policies and in so doing invalidates all waivers that are currently applied. This behaviour is the same as that exhibited
    when uploading a new policy.json file. ** YOU HAVE BEEN WARNED! **

    When on-boarding development teams, you may find the dev-team-onboarding-template.json file helpful. This provides the data-set that pertains to organisation
    and application configuration, aligned to recommended best practice.

    If you are configuring Sonatype Lifecycle for the first time, you may wish to 'apply' the sonatype-recommended-system-config.json and
    sonatype-recommended-root-configuration.json before on-boarding development teams. You will need to adjust the system config settings for LDAP and Email, but
    these defaults are a good prompt to tend to these important configuration items.

Usage: iq-healthcheck [ARGS]...

  Example usage:

    # Run python script though docker container with all packages installed on it!
    docker run --rm -i -v $PWD:/data sonatypecommunity/iq-config-as-code:latest iq-healthcheck -u "http://<iq-hostname>:<iq-port>" -t /data/healthcheck/templates/<template-config>.json

    # Run the script natively on your host
    python3 iq-healthcheck.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp -t healthcheck/templates/App-RBAC-Template.json

    # Healthcheck a specific organisation
    python3 iq-healthcheck.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp -y "My Org" -t healthcheck/templates/Org-RBAC-Template.json

    # Healthcheck a specific application public-id
    # The application public-id is id by which you identify an application when scanning with the cli.
    python3 iq-healthcheck.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp -y "application-x" -t healthcheck/templates/App-RBAC-Template.json

    # Healthcheck a specific organisation(s) and specific application(s) public-id(s)
    python3 iq-healthcheck.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp -y "My Org,Your Org,application-x,application-y"
                                                                                                                -t healthcheck/templates/Org-RBAC-Template.json

    The healthcheck/templates directory contains two template configurations. The sole difference pertains to provisioning of role based access control (RBAC).
    How the template works...

    The template configuration baselines best practice pertaining to the 'Root Organisation'. If you want a specific organisation to deviate from the template
    you must 'scrape' it's data and copy/paste it into the template json file. Thereafter, the 'Template-Org' containing a 'Template-App' configuration exists.
    The configuration of organisations/applications that are not specifically identified by name within the template is benchmarked against the template org/app.
    Output is written to the 'healthcheck' directory by default. The '<Org-Name>-Healthcheck.json' file informs the compliance of your organisation and application
    against the template. The 'Advisories.json' file provides a summary of the healthcheck advisories generated.

    You may be required to adjust the template to align with your SDLC. For example 'Root Organisation' proprietary component matching uses data that must be
    modified in order to align with your company namespaces. The 'policy' configuration utilises role based notifications which ensure stakeholders receive
    notification of new policy violations. Does your business benefit from this capability?

    Please feel free to discuss this with your dedicated CSE or the wider Sonatype Customer Success team: success@sonatype.com

Options:

      -u, --url           Sonatype IQ Server URL                                            # defaults to http://localhost:8070

      -a, --auth          Authentication. <user-id>:<password>                              # defaults to admin:admin123

      -d, --debug         Debug mode.                                                       # defaults to False

      -s, --self_signed   Override validation when a self-signed certificate is installed.  # defaults to False

      -f, --file_name     <config-file>.json                                                # iq-apply_conf.py & iq-healthcheck only

      -o, --output        <output-path>                                                     # iq-scrape-conf.py & iq-healthcheck only - defaults to ./scrape

      -y, --scope         Comma delimited list of org name(s) and/or app public-id(s)       # iq-scrape-conf.py & iq-healthcheck only - defaults to "all"

      -t, --template      The template configuration against which the environment configuration is benchmarked.
                                                                                            # iq-healthcheck.py only

Limitations/Scope:

      These scripts use some private APIs that may change without prior notice.

      SAML configuration is not supported.

      The 'roles' API does not return the role permissionCategories via the GET call. Therefore this data cannot be scraped and persisted.
      Custom Role permissions must be re-applied.

      All password/token values are not returned when scraping config to JSON files. You will need to search the scrape/<config.json>
      file and replace the #~FAKE~SECRET~KEY~# entries.

      The email server account password is null when scraped. A boolean flag to denote password present defaults to 'false'. Be sure to
      address this when editing this data, ahead of applying it to another environment.

      When performing a 'scrape', System-Config.json is always persisted!

      When performing a 'healthcheck', System-Healthcheck.json is always persisted!


Changelog
=========
29th January 2021 - First release

12th February 2021 - Scrape existing IQ config to disk.

26th February 2021 - Scrape to user specified output directory

17th March 2021 - Override self-signed certificate verification

23rd March 2021 - Enable scrape of specific selected application(s) and/or organisation(s)

06th May 2021 - Add healthcheck capability

25th May 2021 - Enhanced healthcheck benchmarks environment configuration against a 'template' configuration aligned with recommended best practice.

13th July 2021 - Improved healthcheck reporting. Templates for on-boarding and healthcheck config aligned to Sonatype recommended best practice.

15th Oct 2021 - API limitation identified. Code to apply policy App Cat scrope 'hard-coded' in scrape script. Persisted data applied to best practice.

5th Nov 2021 - Aforementioned API limitation remediated within product. policyTag data parsed dynamically from json payload.

15th Nov 2021 - Add policyTags to healthcheck analysis.

LICENSE
=========


    Copyright 2019-Present Sonatype Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.


The Fine Print
==============
    It is worth noting that this is NOT SUPPORTED by Sonatype, and is a contribution of ours to the open source community (read: you!)

    Remember:

    Use this contribution at the risk tolerance that you have
    Do NOT file Sonatype support tickets related to this project
    DO file issues here on GitHub, so that the community can pitch in
    Phew, that was easier than I thought. Last but not least of all:

    Have fun creating and using this utility to on-board, persist and health-check your applications into Sonatype Lifecycle. We are glad to have you here!
