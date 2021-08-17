recon
========
Find exploits about a target without ever touching the target


Required
-------
* An internet connection; specicially egress tcp/443
* Register for an API key from shodan.io
* Register for an API key from vuldb.io


Configure
-------
Add your API keys to the `recon.sh` file under the `shodan_api_key` and `vuldb_api_key`
variables.


Examples
-------
Available help system and arguments for tool.
```sh
econ.sh - Research targets

Usage ./recon.sh [options]

 Options:
    -c  Cached time for CVE datasource
    -r  Use existing report
    -t  Targets; supports files, CSV or colon separated lists
    -v  Enable verbosity

```


Default
-------
Default use case will find any public configured address(s) to find
exploits about. It does this by looking at local interfaces and if
only local addresses are found it queries an external API for the
address for the router upstream. When this is done all analysis is
applicable to the upstream comm device.


`./recon.sh`


Existing report
-------
Historical data is available and can be replayed by specifying the
shodan.io report applicable.

`./recon.sh -r reports/shodan-<target>-<date_stamp>-<julian_day_of_year>`


Custom target
-------
At times you may wish to find exploits for other systems.

`./recon.sh -t <target_system>`


Caveats
-------
1. This tool is far from perfect and relies on API's it does not
control or maintain the information available from said sources. As
such false positives and at times no information may be found on a
target.

2. The tool makes all attempts to retain and limit requests to the
API's necessary for reconnasance. The curent cached report time is
`30` days.


API(s) used
-------
Here is a list of the remote API's used by this tool:
* https://ifconfig.me
* https://api.shodan.io
* https://vuldb.com
* https://cve.mitre.org


Disclaimer
-------
This tool provides the user with resources on both existing
vulnerabiliites and where available existing POC tools to help
facilite compromise of a system. Using this tool responsibly will
ensure you do not violate or end up prosecuted under the
Computer Fraud and Abuse Act 18 U.S.C. § 1030
