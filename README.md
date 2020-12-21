# egress0r

Test Firewall and DLP configurations by throwing around packets at the wrong places.

[![asciicast](https://asciinema.org/a/3JzJBEBoyYtFQOwlLsBSn3kH6.svg)](https://asciinema.org/a/3JzJBEBoyYtFQOwlLsBSn3kH6)

No clue what this is about? Read our [blog post](https://cyllective.com/blog/post/egress0r/) about egress0r,
this might give you some insight :)


## Requirements

+ Python 3.6+
+ libcurl-devel for pycurl
+ virtualenv
+ egress0r token*


### egress0r token

Due to unfortunate circumstances we had to restrict access to the public facing egress0r.io services.  
As such, it is now required to sign up for an egress0r token over at [egress0r.io](https://egress0r.io).  

Once you've signed up with your email address and got your token, configure it
in your `config.yml` file under the `auth` configuration section.


## Running local

1. Configure `config.yml` according to your needs, see section [Configuration](#configuration).
2. Initialize the virtualenv: `python3 -m venv venv`
3. Activate the virtualenv: `source ./venv/bin/activate`
4. Install the deps: `PYCURL_SSL_LIBRARY=openssl pip install -r requirements.txt`
5. Run it: `./run.sh`


## Running via Docker

You can run egress0r within a docker container.  
To do that you first build the image (or pull it if you prefer to use a specific tag)
and then launch the container and mount the configuration.

```bash
docker build -t cyllective/egress0r .
docker run --net host -t --rm -v $(pwd)/config.yml:/opt/egress0r/config.yml  cyllective/egress0r
```


## Configuration

Each run of egress0r reads the config file `config.yml`.  
The following sections elaborate on the possible configuration options.

You usually want to copy the provided `config.dist.yml` file to `config.yml`
and apply your configuration in there. It provides you with sane defaults from
which you can build upon.

The following sections define the individual configuration options you can apply.
To get started quickly, it suffices to only replace the `from_addr` in the `smtp` section.


### sanity

The `sanity` section allows you to forcefully enable or disable IPv4 and or IPv6 checks.

| Key           | Accepted values       | Description |
|---------------|-----------------------|-------------|
| override:ipv4 | 'enable' / 'disable' / NULL   | Forcefully enable or disable IPv4 checks, NULL doesn't override |
| override:ipv6 | 'enable' / 'disable' / NULL   | Forcefully enable or disable IPv6 checks, NULL doesn't override |



### auth

The `auth` section allows you to forcefully enable or disable IPv4 and or IPv6 checks.

| Key           | Accepted values       | Description |
|---------------|-----------------------|-------------|
| token         | Your egress0r token   | The egress0r token grants you access to egress0r.io, it is mandatory.
| ipv4_url      | url for ipv4 authentication   | This url points to `https://egress0r.io/auth/ipv4`, this endpoint handles the egress0r token validation. |
| ipv6_url      | url for ipv6 authentication   | This url points to `https://egress0r.io/auth/ipv6`, this endpoint handles the egress0r token validation. |


### check

The `check` section determines which checks are performed.  

| Key  | Accepted values |
|------|-----------------|
| port | true / false    |
| icmp | true / false    |
| http | true / false    |
| smtp | true / false    |
| dns  | true / false    |
| ftp  | true / false    |


### smtp

The `smtp` section configures everything related to SMTP checks.  

| Key     | Accepted values    | Description |
|---------|--------------------|-------------|
| timeout | Integer            | Time in seconds to wait for an answer before aborting |
| host    | Any FQDN           | Which server to use for sending mails |
| port    | Any valid port number | Which port to use for sending mails |
| encrytpion | NULL, tls, ssl | Which encryption mode to use during SMTP negotiation |
| from_addr | Any valid email address | The email address the mail(s) are being sent from |
| to_addr | Any valid email address | The email address to send the mail(s) to |
| username | NULL or string | The username to use for SMTP auth, NULL disables SMTP auth |
| password | NULL or string | The password to use for SMTP auth, NULL disables SMTP auth |
| exfil:filename | filename of a file located in ./egress0r/data | This file is exfiltrated |
| exfil:payload_mode | 'attachment' or 'inline' | defines how the email will contain the data to exfiltrate |
| message | Any string | The default mail body to use during tests |
| subject | Any string | The default subject associated with the mail(s) |


*Note: Be on the lookout for YAML quirks when using complex passwords.  
You might have to escape some chars for the password to work.*


### port

The `port` section configures everything related to the egress port checker. 

| Key     | Accepted values    | Description |
|---------|--------------------|-------------|
| mode | top10, top100, all    | Depending on the mode only 10, 100 or all 65535 ports are checked against |
| ipv4_addr | Any valid IPv4 address | Which IPv4 address to contact to perform the egress port check |
| ipv6_addr | Any valid IPv6 address | Which IPv6 address to contact to perform the egress port check |
| with_tcp | true / false | Enable TCP checking |
| with_udp | true / false | Enable UDP checking |
| tcp_timeout | Any integer| The maximum amount of seconds to wait until terminating a TCP port check |
| udp_timeout | Any integer| The maximum amount of seconds to wait until terminating a UDP port check |


### http

The `http` section configures everything related to the HTTP verb specific exfil checks.  


| Key     | Accepted values    | Description |
|---------|--------------------|-------------|
| timeout | Any integer       | The maximum amount of seconds to wait until terminating an exfil check |
| exfil:filename | Filename of a file located in ./egress0r/data | this file is exfiltrated during the tests |
| verbs   | List of: GET, POST, PUT, PATCH, DELETE | Determines which HTTP verbs are checked |
| urls    | List of: URLs      | Exfiltration checks are performed against those URLs, they should be capable of accepting data on /get, /post, /put and /patch |
| proxies:http | Any valid http proxy | If present this proxy will be used during the exil tests against HTTP based sites |
| proxies:https | Any valid https proxy | If present this proxy will be used during the exfil tests against HTTPS based sites |


### icmp

The `icmp` section configures everything related to the ICMP exfil checks.  


| Key     | Accepted values    | Description |
|---------|--------------------|-------------|
| timeout | Any integer       | The maximum amount of seconds to wait until terminating an exfil check |
| exfil:filename | Filename of a file located in ./egress0r/data | This file is used during the exfil tests |
| exfil:max_chunks | Any integer | Defines the number of chunks to exfiltrate at most |
| exfil:chunk_size | Any integer | Defines how big the chunks are (in bytes) |
| target_hosts | list of IPv4/IPv6 addresses | Defines which hosts are pinged and used during the exfil process |


### dns

The `dns` section configures everything related to the DNS exfil checks.  


| Key     | Accepted values    | Description
|---------|--------------------|-------------
| timeout | Any integer       | The maximum amount of seconds to wait until terminating a DNS query |
| servers | List of IPv4/IPv6 DNS server addresses | Defines *external* DNS servers to use |
| queries | List of `query item` | Defines DNS queries performed against local and external DNS servers |
| `query item`:record | Any valid DNS record | Defines what will be queried |
| `query item`:record_type | One of A, AAAA, MX, TXT, CNAME | Defines which record type should be queried |
| `query item`:expected_answers | List of strings | Optional - after this query item has been resolved we are additionally checking the answer against this list |
| exfil:filename | Filename of a file located in ./egress0r/data | This file is used during the exfil tests |
| exfil:nameserver | Any valid IPv4 or IPv6 address | this nameserver is used during the exfil process |
| exfil:domain | Any domain name | This defines the domain name to use during the exfil process |
| exfil:record_type | Any valid DNS record type | Defines which record type to use during the exfil process |
| exfil:max_chunks | Integer | Defines the number of chunks to exfiltrate at most |
| exfil:chunk_size | Integer | Defines how big the chunks are (in bytes) |



### ftp

The `ftp` section configures everything related to the FTP exfil checks.  


| Key      | Accepted values    | Description
|----------|--------------------|-------------
| timeout  | Any integer        | The maximum amount of seconds to wait until terminating the FTP connection
| host     | Any domain or IP   | The hostname or IP address of the FTP server to exfiltrate data to
| username | String             | The username for FTP auth
| password | String             | The password for FTP auth
| upload_dir | String           | Directory where to upload the data into
| exfil:filename | Filename of a file located in ./egress0r/data | This file is used during the exfil tests

*Note: Be on the lookout for YAML quirks when using complex passwords.  
You might have to escape some chars for the password to work.*


## License

```
Copyright &copy; 2019 cyllective AG

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
```

Refer to the [LICENSE](LICENSE) file for a full copy of the GNU General Public License.


## Terms of Use

You're free to use egress0r against [egress0r.io](https://egress0r.io/).  
Keep in mind that egress0r.io is being monitored and restrictions will be put
in place if the service is abused. *So please be nice. :)*

egress0r.io provides you with the required endpoints to run egress0r, in particular these are:

+ FTP server to test FTP exfil
+ Authoritive DNS server to perform DNS exfil and perform DNS queries over a "not system default" DNS server
+ SMTP echo server to perform SMTP exfil (this echos back the mail you send to `echo@egress0r.io` back to your sending address)
+ [httpbin](https://github.com/postmanlabs/httpbin) to perform GET/POST/PUT/PATCH/DELETE verb specific exfil
+ TCP and UDP listeners on all ports (ports.egress0r.io) to perform egress port checks


## Contributing

We encourage you to submit pull requests and create issues on GitHub.
Feel free to ask questions and file bug reports if you encounter them! :)
