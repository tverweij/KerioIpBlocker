# KerioIpBlocker
Blocks abused IP Addresses

The KerioIPBlocker blocks IP Addresses that are connecting to your environment, but are listed as 100% confident that they are abused.

# Configuration of the Kerio Firewall

**Step 1**

Create a new IP Address Group named *AbuseIP DB Blocked* and add the address 254.254.254.254 with the description *PlaceHolder*

**Step 2**

Create a new Traffic Rule named *Block detected incoming intrusion IP's*, set the Source to the *AbuseIP DB Blocked* address group and everything else to *Any*.
Set the Action to *Drop*

**Step 3**

Create a new Traffic Rule named *Block detected outgoing intrusion IP's*, set the Destination to the *AbuseIP DB Blocked* address group and everything else to *Any*.
Set the Action to *Drop*

# Get an API Key at AbuseIPDB

Go to https://www.abuseipdb.com/pricing and select a plan - then create your account and create your API key

# Schedule the software

Schedule the software on a Windows machine, with start on boot.

The parameters are:
KerioIpBlocker.exe -P:AdminPassword -M:MaxCountOfBlockedAddresses -A:APIKeyForAbuseDB

For MaxCountOfBlockedAddresses:
This is the maximum count of addresses that will be blocked at one time. For performance, don't make this too high.
I myself use 50. 

Each blocked address will be blocked for of 24 hours, or will be freed when the maximum count of addresses is exceeded; in that case the oldest blocked address will be unblocked.
