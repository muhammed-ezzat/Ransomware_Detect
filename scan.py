import os
import argparse
import psutil
import getpass
import hashlib
import re
from collections import namedtuple

ASCII_BYTE = " !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"

String = namedtuple("String", ["s", "offset"])


def ascii_strings(buf, n=4):
    reg = "([%s]{%d,})" % (ASCII_BYTE, n)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        yield String(match.group().decode("ascii"), match.start())


def check_strings(ascii_string, string_file):
    for s in ascii_string:
        ss = '{:s}'.format(s.s)

        for string in string_file:
            if ss == string.rstrip("\n"):
                print '\n\n##################################### Ransomware Malware Detected ###########################################\n\n'
                return

    print '\n\n############################ Safe File #################################\n\n'    


# compare the hashes from the hashes file to the hashes of the identified files
def checkHashe(file):
    # print "scaninng against hash: ", h
    print ("\n\nScanning against hash: \n")

    original_md5 = '84c82835a5d21bbcf75a61706d8ab549'

    md5_returned = hashlib.md5(file).hexdigest()
    print md5_returned
    if original_md5 == md5_returned:
        print "\n\n###################### WANACRY DETECTED ########################\n\n"
    else:
        print "\n\n################## MD5 verification failed! #######################\n\n"


def final_detector_removal():
    print "-----Scanning For Ruuning Malware----"

    while (1):
        # Iterate over all running process
        for proc in psutil.process_iter():

            try:

                # Get process name & pid from process object.

                process_name = proc.name()

                process_ID = proc.pid

                parent_ID = proc.ppid()

                if process_name == "wannacry.exe":
                    print "############################# MALWARE DETECTED #############################  "
                    kill_proc(str(process_ID))  # kill all suspected processes
                    print "Removeing malware"

                elif process_name == "@WanaDecryptor@.exe" or process_name == 'taskhsvc.exe' or process_name == 'taskse.exe' or process_name == 'taskdl.exe':
                    print "#############################  Malawre DETECTED #############################  "

                    kill_proc(str(parent_ID))  # kill parent suspected processes

                    kill_proc(str(process_ID))  # kill all suspected processes

                    print "Removeing malware"

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):

                pass


# kill process function

def kill_proc(pid):
    cmd = "taskkill /F /PID " + pid

    os.system(cmd)


def main():
    parser = argparse.ArgumentParser(description="Scan for malicious files")

    print "Scaninng string of suspicious file"

    parser.add_argument("-D", "--dynamic_analysis",action='store_true')
    parser.add_argument("-S", "--static_analysis",action='store_true')
    parser.add_argument("-A", "--all_types",action='store_true')
    
    parser.add_argument("-f", "--file_suspecis", type=str,
                        help="The directory to scan; the default scan directory is the local directory",
                        )

    parser.add_argument("-w", "--stringfile", type=str,
                        help="File containing a list of malicious strings from known malicious files",
                        default='stringfile.txt')
    


    args = parser.parse_args()
    
    if not args.dynamic_analysis and not args.static_analysis and not args.all_types:
        print('''
            please choose one option
            -S static analysis
            -D dynamic analysis
            -A static and dynamic''')
        exit(0)


    if args.dynamic_analysis:
        final_detector_removal()        
    elif args.static_analysis:
        if args.file_suspecis is None:
            print ('please insert file to analysis -f')
            exit(0)
        stringfile = args.stringfile
        file_suspecis = args.file_suspecis
        with open(file_suspecis, 'rb') as f:  # C:\\Users\\IEUser\\Downloads\\run\\a.exe
            b = f.read()

        file1 = open(stringfile, 'r')  # C:\\Users\\IEUser\\Downloads\\run\\myfile.txt
        Lines = file1.readlines()
        x = ascii_strings(b, n=10)
        check_strings(x, Lines)

        checkHashe(b)
    elif args.all_types:
        if args.file_suspecis is None:
            print ('please insert file to analysis -f')
            exit(0)
        stringfile = args.stringfile
        file_suspecis = args.file_suspecis
        with open(file_suspecis, 'rb') as f:  # C:\\Users\\IEUser\\Downloads\\run\\a.exe
            b = f.read()

        file1 = open(stringfile, 'r')  # C:\\Users\\IEUser\\Downloads\\run\\myfile.txt
        Lines = file1.readlines()
        x = ascii_strings(b, n=10)
        check_strings(x, Lines)

        checkHashe(b)

        final_detector_removal()
        

    
    


if __name__ == '__main__':
    main()

