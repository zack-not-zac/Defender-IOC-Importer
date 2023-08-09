#!/usr/bin/env python3

from pandas import read_csv, DataFrame
import argparse
from datetime import datetime, timedelta
from re import search as regex_search, findall as regex_find, sub as regex_sub
from pathlib import Path

def get_args():
    parser = argparse.ArgumentParser(description="Converts IOC lists to Defender format.")

    # Required Args
    parser.add_argument("file",help="Path to IOC file", metavar="IOC_File")
    parser.add_argument("-c",help="Name of the column containing the IOC's",metavar="IOC_Column",required=True)
    parser.add_argument("-t",help="Title of IOC's", metavar="IOC_Title",required=True)

    # Toggle Args
    parser.add_argument("--hunting_queries",help="Generate a KQL query to hunt for IOC's",action="store_true",)
    parser.add_argument("--no_alerts",help="IOC's should not generate alerts",action="store_false")
    parser.add_argument("--save_URLs",help="Saves URL's as URL indicators. By default, the script extracts the domain & saves as a domain IOC.",action="store_true")

    # Args with restricted choices
    parser.add_argument("-severity",help="Set severity for IOC's",default="Low",choices=["Informational","Low","Medium","High"])
    parser.add_argument("-category",help="Set category for IOC's",default="Malware",choices=["Malware","UnwantedSoftware","Ransomware","CommandandControl","LateralMovement","Persistence","PrivilegeEscalation","SuspiciousActivity","Exploit","InitialAccess","Execution","Exfiltration","Collection","CredentialAccess","DefenseEvasion","Discovery","Impact"])

    # Other Args
    parser.add_argument("-description",help="Set a custom description for IOC's",default="")
    parser.add_argument("-domain_expiry",help="Set expiry for domain & URL IOC's - default = 3 months",default=datetime.utcnow()+timedelta(weeks=12))
    parser.add_argument("-IP_expiry",help="Set expiry for IP IOC's - default = 1 month",default=datetime.utcnow()+timedelta(weeks=4))
    parser.add_argument("-hash_expiry",help="Set expiry for domain & URL IOC's - default = Never",default="")
    parser.add_argument("-actions",help="Set recommended actions for IOC's",default="")
    parser.add_argument("-groups",help="Set RBAC groups for IOC's (comma seperated)",default="")
    parser.add_argument("-techniques",help="Set MITRE Techniques for IOC's (comma seperated)",default="")
    parser.add_argument("-outfile",help="Choose output file path.",default="output.csv")
    return parser.parse_args()

def convert_timestamp(date):
    if date:
        return date.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        return ""

def format_item(item,expiry_dict, args):
    sev = args.severity
    title=args.t
    desc=args.description
    actions = args.actions
    groups=args.groups
    alert=args.no_alerts
    category=args.category
    techniques=args.techniques
    extract_URLs = args.save_URLs

    if len(desc) == 0:
        desc = Path(args.file).stem

    # Regex statements
    domain_re = "([\w\.\-]+\.[\w\-]+(?=\/|:|$))"
    url_re="[\w\.\-]+\/.{1,}"
    ip_re="\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    SHA256_re="^[A-Fa-f0-9]{64}$"
    SHA1_re="^[a-f0-9]{40}$"
    MD5_re="^[a-fA-F\d]{32}$"

    const_columns = [sev,title,desc,actions,groups,category,techniques,str(alert).upper()]

    if regex_search(url_re,item) and extract_URLs:                              # URL IOC
        IOC_type="Url"
        action="Block"                                                          # Valid actions for domain/URL IOC are: Allow, Audit, Warn, Block
        indicator=regex_sub("^https\:\/\/|^http\:\/\/","",item)                 # Removes HTTP & HTTPS
        item_obj = [IOC_type,indicator,convert_timestamp(expiry_dict[IOC_type]),action]            # Extracts domain from a URL
    elif regex_search(ip_re,item):                                              # IP IOC
        IOC_type="IpAddress"
        action="Block"                                                          # Valid actions for IP IOC are: Allow, Audit, Warn, Block
        item_obj = [IOC_type,item,convert_timestamp(expiry_dict[IOC_type]),action]
    elif regex_search(domain_re,item):                                          # Domain IOC
        IOC_type="Domain"
        action="Block"                                                          # Valid actions for domain/URL IOC are: Allow, Audit, Warn, Block
        indicator=regex_sub("^https\:\/\/|^http\:\/\/","",item)                 # Removes HTTP & HTTPS
        indicator = regex_find(domain_re,indicator)[0]                          # Extracts domain from a URL
        item_obj = [IOC_type,indicator,convert_timestamp(expiry_dict[IOC_type]),action]            
    elif regex_search(SHA256_re,item):                                          # SHA256 IOC
        IOC_type="FileSha256"
        action="BlockAndRemediate"                                              # Valid actions for hash IOC are: Allow, Audit, Warn, Block, Block & remediate
        item_obj = [IOC_type,item,convert_timestamp(expiry_dict[IOC_type]),action]
    elif regex_search(SHA1_re,item):                                            # SHA1 IOC
        IOC_type="FileSha1"
        action="BlockAndRemediate"                                              # Valid actions for hash IOC are: Allow, Audit, Warn, Block, Block & remediate
        item_obj = [IOC_type,item,convert_timestamp(expiry_dict[IOC_type]),action]
    elif regex_search(MD5_re,item):                                             # MD5 IOC
        IOC_type="FileMd5"
        action="BlockAndRemediate"                                              # Valid actions for hash IOC are: Allow, Audit, Warn, Block, Block & remediate
        item_obj = [IOC_type,item,convert_timestamp(expiry_dict[IOC_type]),action]
    else:
        print("IOC type for " + str(item) + " not found. Skipping...")
        return None

    return_list = [*item_obj,*const_columns]                                    # Joins the IOC variables & constant columns across all IOCs

    return return_list

def convert_df(IOCs,expiry_dict,args):
    df = DataFrame(columns=["IndicatorType","IndicatorValue","ExpirationTime","Action","Severity","Title","Description","RecommendedActions","RbacGroups","Category","MitreTechniques","GenerateAlert"])

    for i, item in IOCs.items():
        temp = item.replace("[.]",".")                                              # Removes any defanging
        IOC_entry = format_item(temp,expiry_dict,args)
        if IOC_entry:
            df.loc[len(df)] = IOC_entry

    return df

def create_hunting_queries(df):
    SHA256_list = list()
    SHA1_list = list()
    MD5_list=list()
    IPs = list()
    Domains=list()

    for i, row in df.iterrows():
        if row["IndicatorType"] == "Domain" or row["IndicatorType"] == "Url":
            Domains.append(row["IndicatorValue"])
        elif row["IndicatorType"] == "IpAddress":
            IPs.append(row["IndicatorValue"])
        elif row["IndicatorType"] == "FileSha256":
            SHA256_list.append(row["IndicatorValue"])
        elif row["IndicatorType"] == "FileSha1":
            SHA1_list.append(row["IndicatorValue"])
        elif row["IndicatorType"] == "FileMd5":
            MD5_list.append(row["IndicatorValue"])

    print("\nHunting Queries:")

    if len(Domains) > 0:
        print ("\n-------- Domain Search --------\nDeviceNetworkEvents\n| where Timestamp > ago(30d) and RemoteUrl in~ (\"" + "\",\"".join(Domains) + "\")")
    if len(IPs) > 0:
        print ("\n-------- IP Search --------\nDeviceNetworkEvents\n| where Timestamp > ago(30d) and RemoteIP in (\"" + "\",\"".join(IPs) + "\")")
    if len(SHA256_list) > 0 or len(SHA1_list) > 0 or len(MD5_list) > 0:
        print ("\n-------- File Hash Search --------\nDeviceFileEvents\n| where Timestamp > ago(30d) and (SHA256 in~ (\"" + "\",\"".join(SHA256_list) + "\") or SHA1 in~ (\"" + "\",\"".join(SHA1_list) + "\") or MD5 in~ (\"" + "\",\"".join(MD5_list) + "\"))")

def main():
    args = get_args()
    filepath, col = args.file, args.c
    IOC_df = read_csv(filepath)
    expiry_dict = {"Domain":args.domain_expiry,
              "Url":args.domain_expiry,
              "IpAddress":args.IP_expiry,
              "FileSha1":args.hash_expiry,
              "FileSha256":args.hash_expiry,
              "FileMd5":args.hash_expiry}

    Defender_df = convert_df(IOC_df[col],expiry_dict, args).drop_duplicates(subset="IndicatorValue")

    print(Defender_df)
    Defender_df.to_csv(args.outfile,index=False)
    print("\nSaved as " + str(args.outfile))

    if args.hunting_queries:
        create_hunting_queries(Defender_df)
    
    print("\n")

if __name__ == "__main__":
    main()
