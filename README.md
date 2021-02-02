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
from JSON config file(s). This capability supports Sonatype customers aspiration to stand-up/tear-down an IQ 
environment in support of business continuity and service resiliency. 

Configuration is applied in 3 layers:
    1. System
    2. Root Organisation
    3. Child Organisation/Application

The conf directory contains files for individual configuration items in addition to the system-conf.json, root-org-conf.json
and example-org.json that correspond with the aforementioned 3 layers. Default data contained within the config files will 
need to be modified. Please discuss this with your Sonatype CSE.


Usage
$ python3 iq-apply-conf.py --help
Usage: iq-apply-config [ARGS]...

  Example usage:

    # Run python script though docker container with all packages installed on it!
    docker run --rm -i -v $PWD:/tmp broadinstitute/python-requests iq-apply-conf.py -f ./conf/<conf-file>.json -u "http://<iq-hostname>:<iq-port>"

    # Run the script natively on your host
    python3 iq-apply-conf.py -f conf/<conf-file>.json

Options:
  -u, --url           Nexus IQ Server URL
  -a, --auth          Authentication. <user-id>:<password> 
  -f, --file_name     Configuration file. <conf/config.json>
  -d, --debug         Debug mode.

Changelog
=========
29th January 2021
First release

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
