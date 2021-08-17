recon.sh
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
recon.sh - Research targets

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


```sh
$ ./recon.sh
Target: XXX.XXX.XXX.XXX
CVE(s): CVE-2006-6758,CVE-2010-2134,CVE-2013-4407
Exploit(s): https://www.exploit-db.com/explits/11584 https://www.exploit-db.com/explits/2974
```


Existing report
-------
Historical data is available and can be replayed by specifying the
shodan.io report applicable.

```sh
$ ./recon.sh -vr reports/shodan-<TARGET>-<DATESTMP>-<JULAN_DAY_YEAR>
Target: XXX.XXX.XXX.XXX
CVE(s): CVE-2000-0470,CVE-2014-9222,CVE-2014-9223,CVE-2015-9222
Exploit(s): https://www.exploit-db.com/explits/39739
```

Custom target
-------
At times you may wish to find exploits for other systems. Using verbosity.

```sh
$ ./recon.sh -vt <TARGET>
Info: Using <IPv4> <IPv6> as target(s)
Info: Found cached shodan data for <IPv4>...
Info: Found cached shodan data for <IPv6>...
Info: Using 2 report(s) to locate CPE data
Info: Found 8 CPE(s) to search for possible CVE data
Info: Found cached vuldb data for cpe:2.3:a:apache:http:server:2.4.6...
Info: Found cached vuldb data for cpe:a:apache:http:server:2.4.6...
Info: Found cached vuldb data for cpe:2.3:a:apache:http:server:2.4.6...
Info: Found cached vuldb data for cpe:2.3:a:openbsd:openssh:7.4...
Info: Found cached vuldb data for cpe:2.3:a:postfix:postfix...
Info: Found cached vuldb data for cpe:a:apache:http:server:2.4.6...
Info: Found cached vuldb data for cpe:a:openbsd:openssh:7.4...
Info: Found cached vuldb data for cpe:a:postfix:postfix...
Info: Using 8 report(s) to locate possible CVE data
Info: Found 7 CVE(s) applicable to <IPv4> <IPv6>
Info: Using ./assets/20210815-2459441 as CVE datasource
Info: Found 2 exploit(s) for <IPv6>...
Target: <IPv6>
CVE(s): CVE-2006-6758,CVE-2010-2134,CVE-2013-4407
Exploit(s): https://www.exploit-db.com/explits/11584 https://www.exploit-db.com/explits/2974

Info: Found 2 exploit(s) for <IPv4>...
Target: <IPv4>
CVE(s): CVE-2006-6758,CVE-2010-2134,CVE-2013-4407
Exploit(s): https://www.exploit-db.com/explits/11584 https://www.exploit-db.com/explits/2974
```


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
vulnerabiliites and where available, existing POC tools to help
facilite the compromise of a system. Using this tool responsibly
will ensure you do not violate or end up prosecuted under the
Computer Fraud and Abuse Act 18 U.S.C. § 1030
