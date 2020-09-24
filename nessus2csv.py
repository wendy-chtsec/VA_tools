# -*- coding: utf-8 -*-
import argparse
import subprocess
from os import listdir
from os import remove
from os.path import isfile, join
import sys
import io
import xml.etree.ElementTree as ET

def main():
    if args.nessus_file:
        gethostname(args.nessus_file, 0)
    else:
        print('Path of nessus not given. Will convert all nessus.(Enter -h for help)')

        nessus_files = [ f for f in listdir('./') if isfile(join('./',f)) and f.endswith('.nessus') ]
        i = 0
        for f in nessus_files:
            gethostname(f, i)
            print('done: %s.' % (f))
            i += 1
        print('convert all %i files.' % i)
        return

def gethostname(file, i):
    fileroot = ET.parse(file).getroot()
    print('ip'+','+'mac'+','+'nname'+','+'systemtype'+','+'OS'+','+'cpe_0'+','+'cpe_1'+','+'protocol'+','+'port'+','+'svc_name'+','+'output')
    
    mac = ""
    nname = ""
    systemtype = ""
    ip = ""
    OS = ""
    cpe_0 = ""
    cpe_1 = "" 
    i = 0
    tempport = list()
    tempoutput = []
    for path_tot in fileroot.findall('Report/ReportHost'):
        for type_tag in path_tot.findall('HostProperties'):  
            for child in type_tag:
                if child.attrib['name'] == "host-ip":
                    ip = child.text
                if child.attrib['name'] == "mac-address":
                    mac = child.text.replace('\n','_')
                if child.attrib['name'] == "system-type":
                    systemtype = child.text
                if child.attrib['name'] == "netbios-name":
                    nname = child.text
                if child.attrib['name'] == "cpe-0":
                    cpe_0 = child.text
                if child.attrib['name'] == "os":
                    OS = child.text  
                if child.attrib['name'] == "cpe-1":
                    cpe_1 = child.text
                for type_tag in path_tot.findall('ReportItem'):
                    if type_tag.attrib['port'] not in tempport:
                        tempport.append(type_tag.attrib['port'])
                        if ip != "":
                            for output in type_tag:
                                if output.tag =="plugin_output":
                                    str_print = output.text.replace(',','')
                                    str_print = str_print.replace('\r','')
                                    str_print = str_print.replace('\n','')
                                    print('"'+ip+','+mac+','+nname+','+systemtype+','+OS+','+cpe_0+','+cpe_1+','+type_tag.attrib['protocol']+','+type_tag.attrib['port']+','+type_tag.attrib['svc_name']+','+str_print+'"')
                                    break
                                i = i+1
                            i=0

parser = argparse.ArgumentParser(description='nessus host_information and port_information')
parser.add_argument('-f', dest='nessus_file', help='Path of nessus')
args = parser.parse_args()

if __name__ == "__main__": main()