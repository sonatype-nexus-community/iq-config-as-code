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
from where it can be re-applied. This capability supports Sonatype customers aspiration to stand-up/tear-down an IQ 
environment in support of business continuity and service resiliency. 

Configuration is applied in 2 layers:

    1. System

    2. Organization

The conf directory contains files for individual configuration items in addition to the system-conf.json and 
example-org.json that correspond with the aforementioned layers. Default data contained within the config files will 
need to be modified. Please discuss this with your Sonatype CSE.


Usage

    $ python3 iq-scrape-conf.py --help

    $ python3 iq-apply-conf.py --help

Usage: iq-apply-config [ARGS]...

  Example usage:

    # Run python script though docker container with all packages installed on it!
    docker run -w /tmp --rm -i -v $PWD:/tmp broadinstitute/python-requests /tmp/iq-apply-conf.py -f /tmp/conf/<conf-file>.json -u http://<iq-hostname>:<iq-port> -a <user>:<password>

    # Run the script natively on your host
    python3 iq-apply-conf.py -f conf/<conf-file>.json
    python3 iq-apply-conf.py -f scrape/System-Config.json
    python3 iq-apply-conf.py -f scrape/All-Organizations-Config.json


Usage: iq-scrape-config [ARGS]...

  Example usage:

    # Run python script though docker container with all packages installed on it!
    docker run -w /tmp --rm -i -v $PWD:/tmp broadinstitute/python-requests iq-scrape-conf.py -u "http://<iq-hostname>:<iq-port>"

    # Run the script natively on your host
    python3 iq-scrape-conf.py

Options:

      -u, --url           Nexus IQ Server URL

      -a, --auth          Authentication. <user-id>:<password> 

      -d, --debug         Debug mode.

      -f, --file_name     <config-file>.json    # iq-apply_config.py only

Limitations/Scope:

      These scripts use some private APIs that may change without prior notice. 
      
      SAML configuration is not supported.
      
      Policies are nogt supported. See: https://support.sonatype.com/hc/en-us/articles/360008133574

      The 'roles' API does not return the role permissionCategories via the GET call. Therefore this data cannot be scraped and persisted. 
      Custom Role permissions must be re-applied.

      All password/token values are not returned when scraping config to JSON files. You will need to search the scrape/<config.json> 
      file and replace the #~FAKE~SECRET~KEY~# entries.

      The email server account password is null when scraped. A boolean flag to denote password present defaults to 'false'. Be sure to 
      address this when editing this data, ahead of applying it to another environment.
  

Changelog
=========
29th January 2021 - First release

12th February 2021 - Scrape existing IQ config to disk.

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
