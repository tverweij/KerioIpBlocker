# KerioIpBlocker
Blocks abused IP Addresses

The KerioIPBlocker blocks IPv4 Addresses that are connecting to your environment, but are listed as 100% confident that they are abused.
The program doesn't check or block what is already blocked by Kerio. It only blocks malicious IP's that really *connect*.

This software is build in the next generation of Visual Basic - RemObjects Mercury.

**Note** As I have Ipv4 only, the software is not tested with IPv6

# Configuration of the Kerio Firewall

**Step 1**

Create a new IP Address Group named *AbuseIP DB Blocked* and add the address 254.254.254.254 with the description *PlaceHolder*

**Step 2**

Create a new Traffic Rule named *Block detected incoming intrusion IP's*, set the Source to the *AbuseIP DB Blocked* address group and everything else to *Any*.

Set the Action to *Drop* - make sure this is the first rule (op top) in the Traffic Rules.

**Step 3**

Create a new Traffic Rule named *Block detected outgoing intrusion IP's*, set the Destination to the *AbuseIP DB Blocked* address group and everything else to *Any*.

Set the Action to *Drop* - place this rule as second, below the rule in step 2. 

**Step 4**

Any traffice rule (must be of the kind *Allow*) that you want to monitor for abusive connection has to be logged (double-click on the allow column and check *log connections*)

# Get an API Key at AbuseIPDB

Go to https://www.abuseipdb.com/pricing and select a plan - then create your account and create your API key
Depending on your plan, you will have an maximum amount of checks - when your checks for today are exhausted, no new IPAddresses will be blocked as we can not check them anymore.

# Schedule the software

Schedule the software on a Windows machine, with start on boot.

The parameters are:
KerioIpBlocker.exe -P:AdminPassword -M:MaxCountOfBlockedAddresses -A:APIKeyForAbuseDB

For MaxCountOfBlockedAddresses:
This is the maximum count of addresses that will be blocked at one time. For performance, don't make this too high.
I myself use 50. 

Each blocked address will be blocked for 24 hours, or will be freed when the maximum count of addresses is exceeded; in that case the oldest blocked address will be unblocked.

# How does it work?

The software reads the Kerio Control connection log every 15 seconds and all new connections in this log are checked against the AbuseIPDB. To minimize the amount of checks on the internet, the results of those checks are cached (and twice a day a blacklist of minimum 10.000 addresses is downloaded and chached). Every check starts with a check in the cache, if it is found the age of the cached value is checked; when it is older than 24 hours or not in the cache at all, it is rechecked online and the cache will be updated with the new results (and is then again valid for 24 hours). 
When the maximum online checks (based on the plan you chose at AbuseIPDB) are exhaused, the cache is used instead; when an entry is in the cache (no matter what age), this result will be used. When it is not in the cache after the online checks are exhausted, the IP is allowed as we have no way of validating it.
When an IP is blacklisted at AbuseIPDB (means: confidence score of 100%), the IP address is added to the blocking IP Group. And when the maximum amount of blocked IP Addresses is reached, the oldest address in this group is freed to make room for the new address.
The maximum amount of time to remain in the blocked group for an IP address is 24 hours. After that, the address is freed and will only be re-blocked when it tries to connect again.
