# Defender IOC Formatter
A simple Python script to convert CSV documents containing indicators of compromise (IOC's) to the format accepted by Microsoft Defender for Endpoint (MDE). The script can also automatically generate KQL queries for the most common IOC types using the ```"--hunting_queries"``` argument & automatically parses CIDR ranges.

## Installation
This script requires Python 3 to run.

1. Initialise a new virtual environment.
```
python3 -m venv "venv/"
```
2. Activate the virtual environment.
### MacOS & Linux
```
source venv/bin/activate
```
### Windows
```
source venv/Scripts/Activate.ps1
```

3. Install the necessary Python packages.
```
python3 -m pip install -r requirements.txt
```

## Usage

### Example Command

```bash
python3 Defender_IOC_Converter.py ~/Downloads/malware_IOCs.csv -c "Indicator Value" -t "Malware IOC's" --hunting_queries
```

### Help
```
usage: Defender_IOC_Converter.py [-h] -c IOC_Column -t IOC_Title [--hunting_queries] [--no_alerts] [--save_URLs] [-severity {Informational,Low,Medium,High}]
                                 [-category {Malware,UnwantedSoftware,Ransomware,CommandandControl,LateralMovement,Persistence,PrivilegeEscalation,SuspiciousActivity,Exploit,InitialAccess,Execution,Exfiltration,Collection,CredentialAccess,DefenseEvasion,Discovery,Impact}] [-description DESCRIPTION]
                                 [-domain_expiry DOMAIN_EXPIRY] [-IP_expiry IP_EXPIRY] [-hash_expiry HASH_EXPIRY] [-actions ACTIONS] [-groups GROUPS] [-techniques TECHNIQUES] [-outfile OUTFILE]
                                 IOC_File

Converts IOC lists to Defender format.

positional arguments:
  IOC_File              Path to IOC file

options:
  -h, --help            show this help message and exit
  -c IOC_Column         Name of the column containing the IOC's
  -t IOC_Title          Title of IOC's
  --hunting_queries     Generate a KQL query to hunt for IOC's
  --no_alerts           IOC's should not generate alerts
  --save_URLs           Saves URL's as URL indicators. By default, the script extracts the domain & saves as a domain IOC.
  -severity {Informational,Low,Medium,High}
                        Set severity for IOC's
  -category {Malware,UnwantedSoftware,Ransomware,CommandandControl,LateralMovement,Persistence,PrivilegeEscalation,SuspiciousActivity,Exploit,InitialAccess,Execution,Exfiltration,Collection,CredentialAccess,DefenseEvasion,Discovery,Impact}
                        Set category for IOC's
  -description DESCRIPTION
                        Set a custom description for IOC's
  -domain_expiry DOMAIN_EXPIRY
                        Set expiry for domain & URL IOC's - default = 3 months
  -IP_expiry IP_EXPIRY  Set expiry for IP IOC's - default = 1 month
  -hash_expiry HASH_EXPIRY
                        Set expiry for domain & URL IOC's - default = Never
  -actions ACTIONS      Set recommended actions for IOC's
  -groups GROUPS        Set RBAC groups for IOC's (comma seperated)
  -techniques TECHNIQUES
                        Set MITRE Techniques for IOC's (comma seperated)
  -outfile OUTFILE      Choose output file path.
```
