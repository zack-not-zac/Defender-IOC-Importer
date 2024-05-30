#!/usr/bin/env python3

from pandas import read_csv, DataFrame, Series, concat
import argparse
from datetime import datetime, timedelta
from re import search as regex_search, findall as regex_find, sub as regex_sub
from pathlib import Path
from termcolor import colored as text_colour
from ipaddress import IPv4Network

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
    parser.add_argument("-outfile",help="Choose output file path.")
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
    item=str(item).strip()

    if len(desc) == 0:
        desc = Path(args.file).stem

    # Regex statements
    domain_re = "([\w\.\-]+\.[\w\-]+(?=\/|:|$))"
    url_re="[\w\.\-]+\/.{1,}"
    ip_re="\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    SHA256_re="^[A-Fa-f0-9]{64}$"
    SHA1_re="^[A-Fa-f0-9]{40}$"
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
        extracted_ip=regex_search(ip_re,item).group(0)                          # Extracts the IP if it is in a URL
        if extracted_ip:
            item_obj = [IOC_type,extracted_ip,convert_timestamp(expiry_dict[IOC_type]),action]
        else:
            item_obj = [IOC_type,item,convert_timestamp(expiry_dict[IOC_type]),action]
    elif regex_search(domain_re,item):                                          # Domain IOC
        IOC_type="DomainName"
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
        return None

    return_list = [*item_obj,*const_columns]                                    # Joins the IOC variables & constant columns across all IOCs

    return return_list

def convert_df(IOCs,expiry_dict,args):
    df = DataFrame(columns=["IndicatorType","IndicatorValue","ExpirationTime","Action","Severity","Title","Description","RecommendedActions","RbacGroups","Category","MitreTechniques","GenerateAlert"])
    invalid_iocs=list()

    for i, item in IOCs.items():
        temp = item.replace("[.]",".")                                              # Removes any defanging
        IOC_entry = format_item(temp,expiry_dict,args)
        if IOC_entry:
            df.loc[len(df)] = IOC_entry
        else:
            invalid_iocs.append(item)

    return df,invalid_iocs

def create_hunting_queries(df):
    SHA256_list = list()
    SHA1_list = list()
    MD5_list=list()
    IPs = list()
    Domains=list()

    for i, row in df.iterrows():
        if row["IndicatorType"] == "DomainName" or row["IndicatorType"] == "Url":
            Domains.append(row["IndicatorValue"])
        elif row["IndicatorType"] == "IpAddress":
            IPs.append(row["IndicatorValue"])
        elif row["IndicatorType"] == "FileSha256":
            SHA256_list.append(row["IndicatorValue"])
        elif row["IndicatorType"] == "FileSha1":
            SHA1_list.append(row["IndicatorValue"])
        elif row["IndicatorType"] == "FileMd5":
            MD5_list.append(row["IndicatorValue"])

    print("\n-------- Hunting Queries --------")

    if len(Domains) > 0:
        print(text_colour("\n// Domain Hunting Search","green"))
        print("let IOCs = dynamic([\"" + "\",\"".join(Domains) + "\"]);\nunion DeviceNetworkEvents, EmailUrlInfo, UrlClickEvents\n| where Timestamp > ago(30d) and (Url has_any (IOCs) or RemoteUrl has_any (IOCs) or AdditionalFields has_any (IOCs))\n| sort by Timestamp asc")
    if len(IPs) > 0:
        print(text_colour("\n// IP Hunting Search","green"))
        print("let IOCs = dynamic([\"" + "\",\"".join(IPs) + "\"]);\nunion DeviceNetworkEvents, CloudAppEvents, AADSignInEventsBeta\n| where Timestamp > ago(30d) and (IPAddress in (IOCs) or RemoteIP in (IOCs))\n| sort by Timestamp asc")
    if len(SHA256_list) > 0 or len(SHA1_list) > 0 or len(MD5_list) > 0:
        print(text_colour("\n// File Hash Hunting Search","green"))
        SHA256_QueryString = "\",\"".join(SHA256_list)
        SHA1_QueryString = "\",\"".join(SHA1_list)
        MD5_QueryString = "\",\"".join(MD5_list)

        QueryString = str()
        WhereClause = "| where Timestamp > ago(30d) and ("
        Filters = set()

        if len(SHA256_QueryString) > 0:
            QueryString += "let SHA256_IOCs = dynamic([\"" + SHA256_QueryString + "\"]);\n"
            Filters.add("SHA256 in~ (SHA256_IOCs)")
        
        if len(SHA1_QueryString) > 0:
            QueryString += "let SHA256_IOCs = dynamic([\"" + SHA1_QueryString + "\"]);\n"
            Filters.add("SHA1 in~ (SHA1_IOCs)")

        if len(SHA256_QueryString) > 0:
            QueryString += "let MD5_IOCs = dynamic([\"" + MD5_QueryString + "\"]);\n"
            Filters.add("MD5 in~ (MD5_IOCs)")
        
        WhereClause += " or ".join(Filters)
        QueryString += "union DeviceFileEvents, DeviceImageLoadEvents, EmailAttachmentInfo, DeviceProcessEvents" + WhereClause + "\n| sort by Timestamp asc"
        
        print(QueryString)

def parse_cidr(CIDR):
    IPs = IPv4Network(CIDR)
    return_data = list()
    for IP in IPs:
        return_data.append(str(IP))
    return Series(return_data)

def expand_cidr_ranges(IOCs):# Expands any CIDR ranges in the given series, returns the Series with CIDR removed & IP's added
    drop_indexes = set()

    for index,IOC in IOCs.items():
        temp = IOC.replace("[.]",".")                                      # Removes any defanging
        if regex_search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$",temp):
            drop_indexes.add(index)                                        # Adds index to indexes to be removed
            IOCs = concat([IOCs,parse_cidr(temp)], ignore_index=True)      # Add list of IP's from CIDR
            
    for i in drop_indexes:
        IOCs = IOCs.drop(i)

    return IOCs

def write_file(df,outfile):
    df.to_csv(outfile, index=False)
    print("\n[" + text_colour("notice","blue") + "] Saved as " + outfile)

def split_dataframe(df):
    l = len(df.index)
    chunks=list()
    chunk_start=0
    chunk_end=498
    while l > 0:
        chunks.append(df.iloc[chunk_start:chunk_end])       # Append first chunk to list
        l -= 499                                            # subtract 500 from length
        chunk_start = chunk_end + 1                         # set the chunk start to the index after the end of the previous chunk
        if l > 499:                                         # if length is still > 500
            chunk_end += 499                                # set chunk end to 500 rows down
        else:
            chunk_end = len(df.index) - 1                   # else, set the chunk end to the max row index

    return chunks

def main():
    args = get_args()
    filepath, col = args.file, args.c
    IOC_df = read_csv(filepath)
    expiry_dict = {"DomainName":args.domain_expiry,
              "Url":args.domain_expiry,
              "IpAddress":args.IP_expiry,
              "FileSha1":args.hash_expiry,
              "FileSha256":args.hash_expiry,
              "FileMd5":args.hash_expiry}
    
    IOCs = expand_cidr_ranges(IOC_df[col])

    Defender_df,invalid_iocs = convert_df(IOCs,expiry_dict, args)
    Defender_df = Defender_df.drop_duplicates(subset="IndicatorValue")

    print(Defender_df)
    for item in invalid_iocs:
        print(text_colour("[" + text_colour("warning","red") + "] IOC type for '" + str(item) + "' not found. IOC was not added.","red"))

    if len(Defender_df.index) > 500:
        chunks = split_dataframe(Defender_df)
        counter = 0
        for chunk in chunks:
            if args.outfile:
                path = Path(str(args.outfile))
                outfile = str(path.resolve())
                # Add counting for custom filenames
            else:
                outfile = str("Formatted_" + Path(filepath).stem + "_" + str(counter) + ".csv")
            write_file(chunk,outfile)
            counter += 1
    else:
        if args.outfile:
            outfile = str(args.outfile)
        else:
            outfile = str("Formatted_" + Path(filepath).stem + ".csv")
        
        write_file(Defender_df,outfile)

    if args.hunting_queries:
        create_hunting_queries(Defender_df)

    print("\n")

if __name__ == "__main__":
    main()
