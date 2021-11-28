#Dependencies
import sys
import retirejs
import json
import re

#Variables
args = sys.argv

#Main
if len(args) == 1:
    print("python index.js <javascript_link>")
    sys.exit()

print("Scanning the javascript_link, please wait.")
results = retirejs.scan_endpoint(args[1])

if len(results) == 0:
    print("Invalid javascript_link.")
    sys.exit()
elif len(results[0]["vulnerabilities"]) == 0:
    print("No vulnerabilities found in the javascript.")
    sys.exit()
else:
    vulnerabilities = results[0]["vulnerabilities"]
    
    print()
    for vulnerability in vulnerabilities:
        referers = re.sub(r"'", "", str(vulnerability["info"]).replace("[", "").replace("]", ""))
        
        print(f'Name: {vulnerability["identifiers"]["summary"]}\n' +
f'CVE: {vulnerability["identifiers"]["CVE"][0]}\n' +
f'Severity: {vulnerability["severity"]}\n' +
f'Referers: {referers}')
        print()
        
    print(f'{len(vulnerabilities)} vulnerabilities found in the javascript.')
