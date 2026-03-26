This python script will:
- query the RA VPN micro-redirector
- parse the URL response
- use nslookup to return the IP address for the URL
- If DCv2, validate the geo-proximity detection by providing the EDC name
- Count each result for each region.
- The main CNAME for "Auto Select" will also be tested.
- The script only checks USA-based regions

It is advisable to test against different public DNS servers, as geo-proximity uses the DNS server's location and can be variable based on the DNS service provider.

For the AWS regions, verification of the location is not enabled in the script but traceroute can be used to validate.

To run:

chmod +x mr_check.py

python3 mr_check.py

The default script (mr_check.py) uses nslookup from the client operating system.   There is also a _dig version for operating systems that prefer dig.
