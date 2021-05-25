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
# Nexus Lifecycle config-as-code

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


Usage: iq-apply-config [ARGS]...

  Example usage:

    # Run python script though docker container with all packages installed on it!
    docker run -w /tmp --rm -i -v $PWD:/tmp broadinstitute/python-requests /tmp/iq-apply-conf.py -f /tmp/conf/<conf-file>.json -u http://<iq-hostname>:<iq-port> -a <user>:<password>

    # Run the script natively on your host
    python3 iq-apply-conf.py -f conf/<conf-file>.json -a <user>:<password> -u <protocol>://<hostname>:<port>
    
    python3 iq-apply-conf.py -f scrape/System-Config.json  -a <user>:<password> -u <protocol>://<hostname>:<port> -s True
    
    python3 iq-apply-conf.py -f scrape/All-Organizations-Config.json  -a <user>:<password> -u <protocol>://<hostname>:<port>

Usage: iq-healthcheck [ARGS]...

  Example usage:
    
    # Run python script though docker container with all packages installed on it!
    docker run -w /tmp --rm -i -v $PWD:/tmp broadinstitute/python-requests iq-scrape-conf.py -u "http://<iq-hostname>:<iq-port>"

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
    against the template.
    
    You may be required to adjust the template to align with your SDLC. For example 'Root Organisation' proprietary component matching uses data that must be
    modified in order to align with your company namespaces. The 'policy' configuration utilises role based notifications which ensure stakeholders receive
    notification of new policy violations. Does your business benefit from this capability?
    
    Please feel free to discuss this with the Sonatype Customer Success team: success@sonatype.com

Usage: iq-scrape-config [ARGS]...

  Example usage:
    
    # Run python script though docker container with all packages installed on it!
    docker run -w /tmp --rm -i -v $PWD:/tmp broadinstitute/python-requests iq-scrape-conf.py -u "http://<iq-hostname>:<iq-port>"

    # Run the script natively on your host
    python3 iq-scrape-conf.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp

    # Scrape specific organisation
    python3 iq-scrape-conf.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp -y "My Org"

    # Scrape specific application public-id
    # The application public-id is id by which you identify an application when scanning with the cli.
    python3 iq-scrape-conf.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp -y "application-x"

    # Scrape specific organisation(s) and specific application(s) public-id(s)
    python3 iq-scrape-conf.py  -a <user>:<password> -u <protocol>://<hostname>:<port> -o /tmp -y "My Org,Your Org,application-x,application-y"


Options:

      -u, --url           Nexus IQ Server URL                                               # defaults to http://localhost:8070

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
