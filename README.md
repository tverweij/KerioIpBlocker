# KerioIpBlocker
Blocks abused IP Addresses

The KerioIPBlocker blocks IPv4 Addresses that are connecting to your environment, but are listed as 100% confident that they are abused.
The program doesn't check or block what is already blocked by Kerio. It only blocks malicious IP's that really *connect*.

Besides blocking, the software also reports failed connection attemps to the AbuseIPDB.

**Important** If you upgrade, you need to add a new traffic rule, see step 5 at the Configuration of the Kerio Firewall.

Each blocked address will be blocked for 24 hours, or will be freed when the maximum count of addresses is exceeded; in that case the oldest blocked address will be unblocked.


This software is build in the next generation of Visual Basic - RemObjects Mercury.

**Note** As I have Ipv4 only, the software is not tested with IPv6

# Configuration of the Kerio Firewall

**Step 1**

Create a new IP Address Group named *AbuseIP DB Blocked* and add the address 254.254.254.254 with the description *PlaceHolder*

**Step 2**

Create a new Traffic Rule named *Block detected incoming intrusion IP's*, set the Source to the *AbuseIP DB Blocked* address group and everything else to *Any*.

Set the Action to *Drop* - make this rule is the first rules (op top) in the Traffic Rules.

**Step 3**

Create a new Traffic Rule named *Block detected outgoing intrusion IP's*, set the Destination to the *AbuseIP DB Blocked* address group and everything else to *Any*.

Set the Action to *Drop* - place this rule as second, below the rule in step 2. 

**Step 4**

Any traffice rule (must be of the kind *Allow*) that you want to monitor for abusive connection has to be logged (double-click on the allow column and check *log connections*)

**Step 5** (new, needed for reporting of abuse - prevent reporting yourself!)

Create a new Traffic Rule named *Block other traffic from internal networks*, set the Source to the *Trusted/Local Interfaces*, *All VPN Tunnels* and *VPN Clients*, everything else to *Any*. Set the action of this traffic rule to *Drop*, and if you want, log the packets.

Make sure this rule is the last rule in the traffic rules, just before the rule *Block Other Traffic*

*This step is important, as everything that is blocked on the rule Block other traffic will be reported to AbuseIpDB - The creation of this extra rule will make sure that blocked connections from your internal network wont be reported*


# Get an API Key at AbuseIPDB

Go to https://www.abuseipdb.com/pricing and select a plan - then create your account and create your API key
Depending on your plan, you will have an maximum amount of checks - when your checks for today are exhausted, no new IPAddresses will be blocked as we can not check them anymore.

# Schedule the software

Schedule the software on a Windows machine, with start on boot.

The parameters are:
KerioIpBlocker.exe -U:Username -P:Password -M:MaxCountOfBlockedAddresses -A:APIKeyForAbuseDB -R:MinuteToReport

**UserName**
You can supply the username tio use when you are connecting to the Kerion Control Firewall. If you don't supply this parameter, *admin* is used.

**Password**
Mandatory.
The password to use when connecting to the Kerio Control Firewall.

**MaxCountOfBlockedAddresses**
This is the maximum count of addresses that will be blocked at one time. For performance, don't make this too high.
If you don't supply this parameter, 50 will be used.

**APIKeyForAbuseDB**
Mandatory.
The API key that you registered at AbuseIpDB.

**MinuteToReport**
If you don't supply this parameter, no reporting to AbuseIpDB is performed.
The reporting is done every hour, on the minute that you supply with this parameter.
So, if this parameter is 15, the reporting is don at 1:15, 2:15, 3:15 and so on.

# How does it work?

The software reads the Kerio Control connection log every 15 seconds and all new connections in this log are checked against the AbuseIPDB. To minimize the amount of checks on the internet, the results of those checks are cached (and twice a day a blacklist of minimum 10.000 addresses is downloaded and chached). Every check starts with a check in the cache, if it is found the age of the cached value is checked; when it is older than 24 hours or not in the cache at all, it is rechecked online and the cache will be updated with the new results (and is then again valid for 24 hours). 
When the maximum online checks (based on the plan you chose at AbuseIPDB) are exhaused, the cache is used instead; when an entry is in the cache (no matter what age), this result will be used. When it is not in the cache after the online checks are exhausted, the IP is allowed as we have no way of validating it.
When an IP is blacklisted at AbuseIPDB (means: confidence score of 100%), the IP address is added to the blocking IP Group. And when the maximum amount of blocked IP Addresses is reached, the oldest address in this group is freed to make room for the new address.
The maximum amount of time to remain in the blocked group for an IP address is 24 hours. After that, the address is freed and will only be re-blocked when it tries to connect again.
