This python script will:
- query the RA VPN micro-redirector
- parse the URL response
- use nslookup to return the IP address
- If DCv2, validate the geo-proximity detection by providing the EDC name
- Count each result for each region.
- The main CNAME for "Auto Select" will also be tested.

It is advisable to test against different public DNS servers, as geo-proximity uses the DNS server's location and can be variable based on the DNS service provider.
