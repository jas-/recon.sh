recon.sh
========
Find exploits about a target without ever touching the target


Required
-------
* An internet connection; specifically egress tcp/443
* An API key from shodan.io; `shodan_api_key`
* An API key from vuldb.io; `vuldb_api_key`


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
    -c  Cached time for datasources; 30 days
    -r  Use existing report
    -t  Targets; supports files, CSV or colon separated lists
    -v  Enable verbosity

```


Default
-------
Default use case will find any publicly configured address(s) to find
exploits about. It does this by looking at local interfaces and if
only local addresses are found it queries an external API for the
address for the upstream router. When this is done all analysis is
applicable to the upstream comm device.


```sh
$ ./recon.sh
Target: XXX.XXX.XXX.XXX
CVE(s): CVE-2006-6758,CVE-2010-2134,CVE-2013-4407
Exploit(s): https://www.exploit-db.com/exploits/11584 https://www.exploit-db.com/exploits/2974
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
Exploit(s): https://www.exploit-db.com/exploits/11584 https://www.exploit-db.com/exploits/2974

Info: Found 2 exploit(s) for <IPv4>...
Target: <IPv4>
CVE(s): CVE-2006-6758,CVE-2010-2134,CVE-2013-4407
Exploit(s): https://www.exploit-db.com/exploits/11584 https://www.exploit-db.com/exploits/2974
```


Existing report
-------
Historical data is available and can be replayed by specifying the
shodan.io report applicable.

```sh
$ ./recon.sh -vr reports/shodan-<TARGET>-<DATESTMP>-<JULAN_DAY_YEAR>
Target: XXX.XXX.XXX.XXX
CVE(s): CVE-2000-0470,CVE-2014-9222,CVE-2014-9223,CVE-2015-9222
Exploit(s): https://www.exploit-db.com/exploits/39739
```

Caveats
-------
1. This tool is far from perfect due in part to it's reliance on
data provided from external API(s). Be aware of false positives and
the possibility that the target(s) may not have existing scan data
to work with.

2. The tool makes all attempts to retain and limit requests to the
API's necessary for reconnasance. The curent cached report time is
`30` days.

3. The tool ONLY displays those CVE(s) that have existing exploits
for the service associated with the target. So if a system has a
known CVE and NOT an existing exploit available from exploit-db.com
nothing will be presented when there very well could be exising CVE(s)
available.


API(s) used
-------
Here is a list of the remote API's used by this tool:
* https://ifconfig.me
* https://api.shodan.io
* https://vuldb.com
* https://www.exploit-db.com
* https://cve.mitre.org


Disclaimer
-------
This tool provides the user with resources on both existing
vulnerabiliites and where available, existing POC tools to help
facilite the compromise of a system. Using this tool responsibly
will ensure you do not violate or end up prosecuted under the
Computer Fraud and Abuse Act 18 U.S.C. § 1030
