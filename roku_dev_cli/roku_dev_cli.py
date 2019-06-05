# make this run in python2 or 3
from __future__ import print_function
from __future__ import unicode_literals
from .version import __version__

import argparse
import atexit
import datetime
import errno
import fnmatch
import graphviz
import ipaddress
import json
import os
import re
import requests
import shutil
import socket
import subprocess
import sys
import telnetlib
import tempfile
import threading
import time
import traceback
import zipfile

from bs4 import BeautifulSoup
from xml.etree import ElementTree as ET

PROXY_PORT = 8080

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log_color(msg, color, verbose=True):
    if verbose:
        print(u'{}{}{}'.format(color, msg, bcolors.ENDC))

def log_info(msg, **kwargs):
    log_color(msg, bcolors.OKBLUE, **kwargs)

def log_ok(msg, **kwargs):
    log_color(msg, bcolors.OKGREEN, **kwargs)

def log_warn(msg, **kwargs):
    log_color(msg, bcolors.WARNING, **kwargs)

def log_fail(msg, **kwargs):
    log_color(msg, bcolors.FAIL, **kwargs)

proxyProcess = None

# cleans up any child processes
def killChildren():
    if proxyProcess:
        print("killing proxy process")
        proxyProcess.kill()

# prints report paths at the end of the program
reportMessages = []
def reportReminder():
    print("\n")
    for msg in reportMessages:
        print(msg)
    print("\n")

atexit.register(killChildren)
atexit.register(reportReminder)

def deployZip(zipPath, ipAddress, user):
    response = requests.get("http://%s" % ipAddress)

    # new firmware
    if response.status_code == 401:
        print('deploying build to Roku device at %s...' % ipAddress)

        # send a HOME keypress to exit application
        requests.post("http://%s:8060/keypress/home" % ipAddress)

        # TODO: do this using requests library
        cmd = "curl --user {} --digest -s -S -F \"mysubmit=Install\" -F \"archive=@{}\" -F \"passwd=\" http://{}/plugin_install".format(user, zipPath, ipAddress)
        try:
            html = subprocess.check_output(cmd, shell=True)
        except Exception as e:
            msg = bcolors.FAIL + "unable to deploy via curl: " + bcolors.ENDC + cmd
            print(msg)
            exit(1)

        dom = BeautifulSoup(html, 'html.parser')

        for fontTag in dom.find_all('font'):
            line = fontTag.get_text().strip()
            if line:
                print(bcolors.OKBLUE + line + bcolors.ENDC)

    else:
        raise NotImplementedError('script only supports firmware 5+')

class RendezvousStart():
    def __init__(self, index, filePath, lineNumber):
        self.index = index
        self.filePath = filePath
        self.lineNumber = lineNumber

class RendezvousEnd():
    def __init__(self, index, duration):
        self.index = index
        self.duration = duration

class RendezvousReporter():
    def __init__(self):
        self.initialized = False
        self.indexPattern = re.compile('Rendezvous\[([0-9]+)\]')
        self.fileLinePattern = re.compile(r"(\w+:/.*)\(([0-9]+)\)")
        self.completedPattern = re.compile(r"completed in ([0-9]+\.[0-9]+) s")
        self.rendezvousData = {}

    def updateReport(self):
        rByPathAndLine = {}
        fileLineSections = {}
        adjacentRange = 1 # search one line above and below for rendezvous

        with open(self.reportPath, 'w') as fd:
            for rIndex,data in self.rendezvousData.items():
                if data["end"]: # only process rendezvous data with end
                    # calculate the most frequent rendezvous and durations
                    start = data["start"]
                    key = "%s(%i)" % (start.filePath, start.lineNumber)
                    if key not in rByPathAndLine:
                        rByPathAndLine[key] = {
                            "count" : 0,
                            "totalTime" : 0,
                            "longestDuration" : 0
                        }
                    rByPathAndLine[key]["count"] += 1
                    rByPathAndLine[key]["totalTime"] += data["end"].duration
                    rByPathAndLine[key]["longestDuration"] = max(rByPathAndLine[key]["longestDuration"], data["end"].duration)

                    # make an array of lines and mark the line with rendezvous as True
                    filePath = start.filePath
                    if filePath not in fileLineSections:
                        fileLineSections[filePath] = {
                            "rendezvousLines" : []
                        }
                    lineNumber = start.lineNumber
                    rendezvousLines = fileLineSections[filePath]["rendezvousLines"]
                    while lineNumber >= len(rendezvousLines): # make sure it's big enough
                        rendezvousLines.extend([False] * 100)
                    rendezvousLines[lineNumber] = True

            fd.write("=== Rendezvous by Frequency ===\n")
            for pathAndLine,stats in sorted(rByPathAndLine.items(), key=lambda kv: kv[1]["count"], reverse=True):
                averageDuration = stats["totalTime"] / stats["count"]
                fd.write("%i - %s (avg. duration: %.3fs)\n" % (stats["count"], pathAndLine, averageDuration))

            fd.write("\n")

            fd.write("=== Rendezvous by Longest Single Duration ===\n")
            for pathAndLine,stats in sorted(rByPathAndLine.items(), key=lambda kv: kv[1]["longestDuration"], reverse=True):
                fd.write("%2.3fs - %s\n" % (stats["longestDuration"], pathAndLine))

            fd.write("\n")

            fd.write("=== Adjacent Rendezvous (opportunity to use `queueFields`?) ===\n")

            for filePath,stats in fileLineSections.items():
                rendezvousLines = stats["rendezvousLines"]

                adjacentLines = []
                for lineNumber in range(0, len(rendezvousLines)):
                    if rendezvousLines[lineNumber]: # this line has a rendezvous, search adjacent lines
                        for adjacentLineNumber in range(lineNumber-adjacentRange, lineNumber+adjacentRange+1):
                            if adjacentLineNumber > -1 and adjacentLineNumber < len(rendezvousLines) and lineNumber != adjacentLineNumber:
                                if rendezvousLines[adjacentLineNumber]:
                                    adjacentLines.append(lineNumber)
                                    break

                # hyphenate ranges
                ranges = self.hyphenateRanges(adjacentLines, adjacentRange)  

                if len(ranges) > 0:
                    fd.write("%s - lines adjacent to other rendezvous: %s\n" % (filePath, ", ".join(ranges)))

    # takes a list of int-formatted line numbers and groups them into hyphenated ranges
    def hyphenateRanges(self, adjacentLines, adjacentRange):
        ranges = []
        for adjacentLine in adjacentLines:
            if len(ranges) == 0:
                ranges.append("%s-%s" % (adjacentLine, adjacentLine))
            else:
                lastRange = ranges[-1]
                firstLineNumber, lastLineNumber = lastRange.split("-") # get last number in last range
                if adjacentLine - int(lastLineNumber) < adjacentRange+1: # tack on to existing range
                    ranges[-1] = "%s-%s" % (firstLineNumber, adjacentLine)
                else: # start a new range
                    ranges.append("%s-%s" % (adjacentLine, adjacentLine))
        return ranges

    # setup a report file for writing
    def initialize(self):
        with tempfile.NamedTemporaryFile(prefix='rendezvous_report_', suffix='.txt', delete=False) as fd:
            self.reportPath = fd.name

        with open(self.reportPath, 'w') as fd:
            fd.write("no rendezvous logs processed\n") # placeholder until logs actually written

        msg = bcolors.OKBLUE + "writing rendezvous report: %s" % self.reportPath + bcolors.ENDC
        print(msg)
        reportMessages.append(msg)

    # process a given line of telnet output (ignores non-rendezvous-related lines)
    def processLine(self, line):
        if not self.initialized: # doing this lazily so it doesn't show up in testing
            self.initialize()
            self.initialized = True
        try:
            lineInfo = self.parseLine(line)
        except ValueError as e:
            print(bcolors.FAIL + "reporter unable to parse line: %s" % line + bcolors.ENDC)

        if isinstance(lineInfo, RendezvousStart):
            self.rendezvousData[lineInfo.index] = {
                "start" : lineInfo,
                "end" : None
            }
        elif isinstance(lineInfo, RendezvousEnd):
            if lineInfo.index in self.rendezvousData:
                self.rendezvousData[lineInfo.index]["end"] = lineInfo
                self.updateReport()
            else:
                print(bcolors.FAIL + "no rendezvous start for reported end: %i" % lineInfo.index + line + bcolors.ENDC)
        
    def parseLine(self, line):
        if "sg.node.BLOCK" in line:
            return RendezvousStart(
                int(self.parseRendezvousIndex(line)), 
                self.parseFilePath(line),
                int(self.parseLineNumber(line))
            )
        elif "sg.node.UNBLOCK" in line:
            return RendezvousEnd(
                int(self.parseRendezvousIndex(line)), 
                float(self.parseRendezvousDuration(line))
            )
        else:
            return None

    # find the index of the rendezvous in the log line
    def parseRendezvousIndex(self, line):
        matches = self.indexPattern.search(line).groups(0)
        if len(matches) == 1:
            return matches[0]
        else:
            raise ValueError("unable to parse index")

    # find the file path in the line
    def parseFilePath(self, line):
        matches = self.fileLinePattern.search(line)
        if not matches or len(matches.groups()) != 2:
            raise ValueError("unable to parse file path")
        else:
            groups = matches.groups()
            return groups[0]

    def parseLineNumber(self, line):
        matches = self.fileLinePattern.search(line)
        if not matches or len(matches.groups()) != 2:
            raise ValueError("unable to parse file number")
        else:
            groups = matches.groups()
            return groups[1]        

    def parseRendezvousDuration(self, line):
        matches = self.completedPattern.search(line)
        if matches:
            groups = matches.groups()
            return groups[0]
        elif line.strip().endswith("completed"):
            return "0.000" # completed in under 1 millisecond
        else:
            raise ValueError("unable to parse duration")

class ConsoleListener(threading.Thread):
    def __init__(self, ip, timestamp, report_rendezvous):
        super(ConsoleListener, self).__init__()

        self.ip = ip
        self.port = 8085
        self.daemon = True
        self.timestamp = timestamp # show a timestamp before log output
        self.reporters = []
        if report_rendezvous:
            self.reporters.append(RendezvousReporter())

    def run(self):
        debuggerHighlights = set([
            "BrightScript Micro Debugger.",
            "Enter any BrightScript statement, debug commands, or HELP.",
            "Current Function:",
            "Backtrace:",
            "Local Variables:",
            "Brightscript Debugger>"
            ""
        ])
        try:
            self.session = telnetlib.Telnet(self.ip, self.port)
            while True:
                text = self.session.read_until(b"\n", 1)
                if text:
                    text = text.decode('utf-8')
                    #removes logs from previous sessions
                    compileIndex = text.rfind("------ Compiling")
                    if compileIndex != -1:
                        text = text[compileIndex:]
                    for line in text.split('\n'):
                        if line:
                            for reporter in self.reporters:
                                reporter.processLine(line)

                            if self.timestamp:
                                timestamp = datetime.datetime.now().strftime('%h %d, %Y %I:%M:%S%p')
                                line = bcolors.OKBLUE + "[" + timestamp + "] " + bcolors.ENDC + line

                            # add red to highlight debugger output
                            if line.strip() in debuggerHighlights:
                                print(bcolors.FAIL + line + bcolors.ENDC)
                            else:
                                print(line)

        except EOFError as e:
            print(e)
            print(bcolors.FAIL + "telnet timed out on port %i" % self.port + bcolors.ENDC)
        except Exception as e:
            traceback.print_exc()
            print(bcolors.FAIL + "something rather bad happened :(" + bcolors.ENDC)

# super class that handles buckets
class Poller(object):
    def __init__(self):
        self.buckets = []

    def addBucket(self, bucket):
        bucket.update()
        self.buckets.append(bucket)

    def getBucketAttr(self, attr):
        bucket = self.buckets[-1]
        if attr not in bucket:
            bucket[attr] = {}
        return bucket[attr]

    def process(self, text):
        if len(self.buckets) > 0:
            self.processText(text)

# polls for the number of nodes at a given time
class NodePoller(Poller):
    def processText(self, text):
        tagCounts = self.getBucketAttr("tagCounts")

        openingTags = re.findall("<([A-Za-z0-9_]+)", text)
        for tag in openingTags:
            if tag not in tagCounts:
                tagCounts[tag] = 0
            tagCounts[tag] += 1

    def writeReport(self, reportDir):
        # clean up the buckets a bit
        tagNames = set()
        for bucket in self.buckets:
            for tagName in bucket["tagCounts"].keys():
                tagNames.add(tagName)
        for bucket in self.buckets:
            for tagName in tagNames:
                if tagName not in bucket["tagCounts"]:
                    bucket["tagCounts"][tagName] = 0

        bucketPath = os.path.join(reportDir, "nodes.js")
        with open(bucketPath, "w") as fd:
            fd.write("function getNodeBuckets() { return %s; }\n" % json.dumps(self.buckets))

    def command(self):
        return "sgnodes all"

# polls the texture memory at a given time
class TextureMemoryPoller(Poller):
    def processText(self, text):
        memory = re.findall("Available memory (\d+) used (\d+) max (\d+)", text)
        if len(memory) > 0:
            memoryStatus = self.getBucketAttr("texture_memory")
            # use second value, first seems to be for something else
            memoryStatus["available"], memoryStatus["used"], memoryStatus["maximum"] = memory[0]

    def writeReport(self, reportDir):
        bucketPath = os.path.join(reportDir, "texture_memory.js")
        with open(bucketPath, "w") as fd:
            fd.write("function getTextureMemoryBuckets() { return %s; }\n" % json.dumps(self.buckets))

    def command(self):
        return "r2d2_bitmaps"

class SystemMemoryPoller(Poller):
    def processText(self, text):
        memory = re.findall("Mem:\W+(\d+)\W+(\d+)", text)
        if len(memory) is 1: # found something
            memoryStatus = self.getBucketAttr("system_memory")
            memoryStatus["total"], memoryStatus["used"] = memory[0]
            print("system memory: %s used, %s total" % (memoryStatus["used"], memoryStatus["total"]))

    def writeReport(self, reportDir):
        bucketPath = os.path.join(reportDir, "system_memory.js")
        with open(bucketPath, "w") as fd:
            fd.write("function getSystemMemoryBuckets() { return %s; }\n" % json.dumps(self.buckets))

    def command(self):
        return "free"

class PollingListener(threading.Thread):
    def __init__(self, ip):
        super(PollingListener, self).__init__()

        self.ip = ip
        self.port = 8080
        self.daemon = True
        self.lastPoll = time.time()
        self.pollInterval = 1 # frequency to check node count (in seconds)

        self.reportName = "report_%i" % int(time.time())
        self.pollers = [ NodePoller(), SystemMemoryPoller(), TextureMemoryPoller() ] # cycle between these
        self.pollerIndex = 0

        self.reportDir = self.createReportDir()

    def run(self):
        try:
            self.session = telnetlib.Telnet(self.ip, self.port)
            while True:
                text = self.session.read_until(b"\n")
                if text:
                    poller = self.pollers[self.pollerIndex]
                    poller.process(text)
                    poller.writeReport(self.reportDir)

                elif time.time() - self.lastPoll > self.pollInterval: # check if we need to request more data
                    self.pollerIndex = (self.pollerIndex + 1) % len(self.pollers) # switch to the next poller
                    poller = self.pollers[self.pollerIndex]

                    self.lastPoll = time.time()
                    poller.addBucket({
                        "startTime": self.lastPoll
                    })
                    self.session.write(poller.command() + "\n")

        except Exception as e:
            print(e)
            print(bcolors.FAIL + "telnet node listener timed out on port %i" % self.port)

    def createReportDir(self):
        tempDir = tempfile.gettempdir()
        reportsDir = os.path.join(tempDir, "node_reports")
        if not os.path.exists(reportsDir):
            os.mkdir(reportsDir)

        reportDir = os.path.join(reportsDir, self.reportName)
        if not os.path.exists(reportDir):
            os.mkdir(reportDir)

            basePyPath = os.path.dirname(os.path.realpath(__file__))
            htmlFile = os.path.join(basePyPath, "reports", "index.html")
            shutil.copy2(htmlFile, os.path.join(reportDir, "index.html"))

            msg = bcolors.OKBLUE + "writing node report: %s" % os.path.join(reportDir, "index.html") + bcolors.ENDC
            print(msg)
            reportMessages.append(msg)

        return reportDir

def validateXmlCwd():
    # validate xml files
    print("validating xml files in components...")
    for root, dirnames, filenames in os.walk("components"):
        for filename in fnmatch.filter(filenames, '*.xml'):
            path = os.path.join(root, filename)
            with open(path, "r") as f:
                xmlContents = f.read()
                try:
                    ET.fromstring(xmlContents)
                except Exception as e:
                    print(bcolors.FAIL + "error parsing " + path + ": " + str(e.message) + bcolors.ENDC)
                    exit(1)
    print("   success!\n")

# create graph of node inheritance
def analyzeCwd():
    # validate xml files
    print("validating xml files in components...")
    xmlPaths = []
    for root, dirnames, filenames in os.walk("components"):
        for filename in fnmatch.filter(filenames, '*.xml'):
            path = os.path.join(root, filename)
            xmlPaths.append(path)

    def createComponent():
        return {
            "children": [],
            "scripts": [],
            "parent": None
        }

    components = {}
    for xmlPath in xmlPaths:
        with open(xmlPath, "r") as f:
            xmlContents = f.read()
            root = ET.fromstring(xmlContents)
            componentName = root.attrib["name"]
            if componentName not in components:
                components[componentName] = createComponent()
            if "extends" in root.attrib:
                parentName = root.attrib["extends"]
                if parentName not in components:
                    components[parentName] = createComponent()

                # link child to parent, parent to child
                components[componentName]["parent"] = parentName
                components[parentName]["children"].append(componentName)
            for child in root:
                if child.tag == "script" and "uri" in child.attrib:
                    components[componentName]["scripts"].append(child.attrib["uri"])

    dot = graphviz.Graph(comment='Node Inheritance', format="jpg")
    for componentName in components:
        dot.node(componentName)
        component = components[componentName]
        for childName in component["children"]:
            dot.edge(componentName, childName)

        if component["parent"] not in components:
            checkDuplicateScripts(componentName, components, [])

    file_path = "/tmp/inheritance"
    dot.render(file_path)
    print("created node inheritance graph: %s.jpg" % file_path)

def checkDuplicateScripts(componentName, components, totalScripts):
    component = components[componentName]
    for script in component["scripts"]:
        if script in totalScripts:
            print(bcolors.FAIL + "FOUND DUPLICATE SCRIPT FROM " + componentName + " with script: " + script + bcolors.ENDC)

    for childName in component["children"]:
        checkDuplicateScripts(childName, components, totalScripts + component["scripts"])

# returns a manifest as a string based on the existing manifest file, but replacing any keys
# with matching environment variables
def getDynamicManifest():
    with open('./manifest', 'r') as fd:
        lines = fd.readlines()
        for i,line in enumerate(lines):
            lines[i] = line.strip()
            try:
                tokens = line.split("=")
                if tokens[0] == "bs_const":
                    key = tokens[1]
                else:
                    key = tokens[0]
                value = tokens[-1]
                if key in os.environ: # replace with environment variable
                    msg = "replacing manifest property '%s' with env value: %s" % (key, os.environ[key])
                    print(bcolors.OKBLUE + msg + bcolors.ENDC)
                    lines[i] = line.replace(value, os.environ[key])

            except Exception:
                pass # silently skip any lines without an equality

        return "\n".join(lines) + "\n"

def getProxyFile(path):
    """
    Opens a text file and returns the contents with any setting of a certificate file
    replaced with the mitmproxy certificate.
    """
    with open(path, "r") as fd:
        contents = fd.read()
        certReferences = re.findall("setcertificatesfile\(.*\)", contents, re.IGNORECASE)
        for certReference in certReferences:
            msg = "using mitmproxy certificate: %s (%s)" % (certReference, path)
            print(bcolors.OKBLUE + msg + bcolors.ENDC)
            contents = contents.replace(certReference, 'setCertificatesFile("pkg:/source/mitmproxy.crt")')

        return contents

def getProxyCertificate():
    """
    Returns the mitmproxy certificate file contents as a string.
    """
    certificatePath = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
    if not os.path.exists(certificatePath):
        raise Exception("mitmproxy file not found: %s" % certificatePath)

    with open(certificatePath, "r") as fd:
        return fd.read()

def createZipFromCwd(proxy, additionalPaths, package_all):
    """
    Creates a zip file from the current directory.  The manifest and references to the cert
    file can be dynamically altered at zip time.

    Arguments:
    proxy - boolean as to whether to replace cert references with references to mitmproxy
    additionalPaths - list of directories not normally included in the zip file
    package_all - Package everything under the folder. If set, additionalPaths will be ignored.
    """
    # zip up build and send it to machine
    with tempfile.NamedTemporaryFile(prefix='roku_build.', suffix='.zip', delete=False) as tempFile:
        with zipfile.ZipFile(tempFile, 'w', compression=zipfile.ZIP_DEFLATED) as zipFile:
            def addFile(path):
                if proxy and (path.endswith(".brs") or path.endswith(".xml")):
                    zipFile.writestr(path, getProxyFile(path))
                else:
                    zipFile.write(path)

            def addDirectory(path):
                for root, dirs, files in os.walk(path):
                    for f in files:
                        path = '%s/%s' % (root, f)
                        addFile(path)

            if package_all:
                # walk dir, add stuff
                addDirectory('.')
            else:
                # add manifest
                zipFile.writestr('manifest', getDynamicManifest())

                # add images
                addDirectory('images')

                # add source code
                addDirectory('source')

                # add fonts
                addDirectory('fonts')

                # add components
                addDirectory('components')

                # add additional directories specified
                for path in additionalPaths:
                    addDirectory(path)

            # if proxying copy over the mitmproxy certificate
            if proxy:
                zipFile.writestr('source/mitmproxy.crt', getProxyCertificate())

    msg = "created zip package: %s" % tempFile.name
    print(bcolors.OKBLUE + msg + bcolors.ENDC)

    tempFile.close()

    return tempFile.name

# returns the mitmproxy version of the command-line tool as a tuple (ex. (2,0,2) )
def getMitmProxyVersion():
    cmd = "mitmproxy --version"
    try:
        output = subprocess.check_output(cmd, shell=True)
        match = re.search("Mitmproxy(?:\s*version)?: (?P<mitmVersion>\d+.\d+.\d+)", output.decode("utf-8"))
        versionStr = match.group("mitmVersion")
        major, minor, micro = versionStr.split(".")
        print("detected mitmproxy version: " + versionStr)
        return (int(major), int(minor), int(micro))
    except:
        pass

    msg = bcolors.FAIL + "unable to query mitmproxy version" + bcolors.ENDC
    print(msg)
    exit(1)

def startProxy(proxyScripts, proxyExclude, useWebUi):
    """Create valid IPAddress object or None
    :param list proxyScripts: list of scripts by path that mitm will execute on proxy requests
    :param list proxyExclude: list of domains the proxy script will exclude from inspection
    :param bool useWebUi: `True` if `mitmweb` should be used instead of `mitmdump`, otherwise `False`
    """
    global proxyProcess

    if proxyExclude == None:
        proxyExclude = []

    # NICE-TO-HAVE TODO: somehow verify cross-platform that HTTP/HTTPS is redirecting to 8080

    excludedHosts = ["s-video.innovid.com", "roku.com", "brightline.tv", "license.\w+.com"] + proxyExclude

    hostsRegex = "(%s):\d+$" % "|".join(excludedHosts)
    command = ["mitmweb", "--no-web-open-browser"] if useWebUi else ["mitmdump"]
    if getMitmProxyVersion()[0] == 2:
        command.extend(["-T", "--host", "--ignore", hostsRegex])
    else: # assume 3+
        command.extend(["--mode", "transparent", "--showhost", "--ignore-hosts", hostsRegex])

    if proxyScripts is not None:
        [command.extend(["-s", script]) for script in proxyScripts]

    proxyProcess = subprocess.Popen(command)

def str2list(str, delim=';'):
    strs = (u'' + str).split(delim) # convert to Unicode and split
    strs = map((lambda s: s.strip()), strs) # strip each element
    strs = filter((lambda s: s), strs) # reject empty elements
    return list(strs) # resolve iterable to list

def validIp(ipUnicode, verbose=True):
    """Create valid IPAddress object or None
    :param str ipUnicode: An IP address as a Unicode string.
    :param bool verbose: Set to false to suppress log output.
    :return: An IPAddress object if `ipUnicode` is well-formed; otherwise None.
    :rtype: IPAddress or None
    """
    ip = None
    try:
        ip = ipaddress.ip_address(ipUnicode)
    except ValueError as e:
        log_info(e, verbose=verbose)
    return ip

def reachableIp(ipUnicode, verbose=True):
    """Create reachable IPAddress object or None
    :param str ipUnicode: An IP address as a Unicode string.
    :param bool verbose: Set to false to suppress log output.
    :return: An IPAddress object if `ipUnicode` responds successfully to
        ping; otherwise None.
    :rtype: IPAddress or None
    """
    ip = validIp(ipUnicode, verbose=verbose)
    if ip and os.system("ping -q -n -c 1 -W 500 {} &> /dev/null".format(ip)):
        log_info('{} is not reachable'.format(ipUnicode), verbose=verbose)
        ip = None
    return ip

def rokuIp(ipUnicode, verbose=True):
    """Create reachable, Roku IPAddress object or None
    :param str ipUnicode: An IP address as a Unicode string.
    :param bool verbose: Set to false to suppress log output.
    :return: An IPAddress object if `ipUnicode` responds successfully to
        a Roku device-info query; otherwise None.
    :rtype: IPAddress or None
    """
    ip = reachableIp(ipUnicode, verbose=verbose)
    if ip and os.system('curl -s --connect-timeout .5 -o /dev/null "http://{}:8060/query/device-info"'.format(ip)):
        log_info('{} is not a Roku device'.format(ipUnicode), verbose=verbose)
        ip = None
    return ip

def findRokuIp(ipUnicodes, verbose=True):
    """Find first reachable, Roku IP address as an IPAddress object or None
    :param list[str] ipUnicodes: A list of IP addresses as Unicode strings.
    :param bool verbose: Set to false to suppress log output.
    :return: An IPAddress object for the first address in `ipUnicodes` that
        responds successfully to a Roku device-info query; otherwise None.
    :rtype: IPAddress or None
    """
    log_info('Finding Roku devices in {}'.format(ipUnicodes))
    ip = next((ipUnicode for ipUnicode in ipUnicodes if rokuIp(ipUnicode, verbose=verbose)), None)
    if not ip:
        log_fail('No reachable Roku device found in {}'.format(ipUnicodes), verbose=verbose)
        exit(1)
    log_ok('{} is a Roku device'.format(ip), verbose=verbose)
    return ip

def selectRokuIps(ipUnicodes, verbose=True):
    """Create list of reachable, Roku IPAddress objects.
    :param list[str] ipUnicodes: A list of IP addresses as Unicode strings.
    :param bool verbose: Set to false to suppress log output.
    :return: A list of IPAddress objects for addresses in `ipUnicodes` that
        respond successfully to a Roku device-info query. May be empty.
    :rtype: list[IPAddress]
    """
    log_info('Finding Roku devices in {}'.format(ipUnicodes), verbose=verbose)
    rokuIpQuiet = lambda ipUnicode: rokuIp(ipUnicode, verbose=False)
    ips = filter(rokuIpQuiet, ipUnicodes)
    log_ok('Found the following Roku devices {}'.format(ips), verbose=verbose)
    return ips

def main():
    parser = argparse.ArgumentParser(description='Uploads builds to the device and telnets into the machine for logging')

    parser.add_argument('-v', '--version', action='version', version='roku-dev-cli {}'.format(__version__))
    parser.add_argument('-t', action='store_true', help="display timestamp in front of each line")
    parser.add_argument('-n', action='store_true', help="track node usage over time")
    parser.add_argument('--report-rendezvous', action='store_true', help='reports telnet rendezvous events to file')
    parser.add_argument('-i', '--inheritance', action='store_true', help="analyze file inheritance")

    parser.add_argument('-z', '--zip-file', nargs=1, type=str, help="zip file to load onto the Roku") # hyphen-spelling shown in help
    parser.add_argument('--zip_file', nargs=1, type=str, help=argparse.SUPPRESS) # underscore_spelling supported but not shown in help

    parser.add_argument('--save-only', action='store_true', help="just creates the xml but doesn't deploy")
    parser.add_argument('--save_only', action='store_true', help=argparse.SUPPRESS)

    parser.add_argument('-a', '--automation', action='store_true', help="creates an automation build")
    parser.add_argument('-p', '--proxy', action='store_true', help="builds the app to proxy through this host")

    parser.add_argument('-s', '--proxy-scripts', nargs='+', help='Provide paths to proxy add-on scripts')
    parser.add_argument('--proxy_scripts', nargs='+', help=argparse.SUPPRESS)

    parser.add_argument('-w', '--web', action='store_true', help='Uses mitmweb to provide a browser-based network monitor')

    parser.add_argument('--proxy-exclude', nargs='+', help='Provide regex-formatted domains that will be exclude by proxy filter')
    parser.add_argument('--proxy_exclude', nargs='+', help=argparse.SUPPRESS)

    parser.add_argument('--check-ip', action='store_true', help="Checks for at least one, reachable, Roku IP address")
    parser.add_argument('--check_ip', action='store_true', help=argparse.SUPPRESS)

    parser.add_argument('--select-roku-ips', action='store_true', help="Filters list of IPs and returns all valid, reachable, roku IPs in list.")
    parser.add_argument('--select_roku_ips', action='store_true', help=argparse.SUPPRESS)

    parser.add_argument('--package_all', action='store_true', help="Add everything under the folder into the target package. If set, automation flag will be ignored.")

    parser.add_argument(
        '-u',
        '--user',
        default=os.environ.get('ROKU_DEV_USER'),
        help='Roku device username:password, defaults to $ROKU_DEV_USER'
    )

    parser.add_argument(
        'ipUnicodes',
        type=str2list,
        nargs='?',
        default=os.environ.get('ROKU_DEV_TARGET', ''),
        metavar='ip_address(es)',
        help='semicolon-delimited list of Roku device IP addresses, defaults to $ROKU_DEV_TARGET'
    )

    args = parser.parse_args()

    if args.select_roku_ips:
        selectRokuIps(args.ipUnicodes, verbose=True)
        exit(0)

    ip = None if args.save_only else str(findRokuIp(args.ipUnicodes, verbose=True))

    if args.check_ip:
        exit(0)

    useProxy = args.proxy
    proxyScripts = args.proxy_scripts
    proxyExclude = args.proxy_exclude
    useWebUi = args.web

    # start mitmproxy
    if useProxy:
        startProxy(proxyScripts, proxyExclude, useWebUi)

    # if we aren't using proxy but user specified scripts to load
    elif proxyScripts is not None:
        print("'--proxy_scripts' argument can only be used if '--proxy' argument is also specified")
        exit(1)

    elif proxyExclude is not None:
        print("'--proxy_exclude' argument can only be used if '--proxy' argument is also specified")
        exit(1)

    elif useWebUi:
        print("'--web' argument can only be used if '--proxy' argument is also specified")
        exit(1)


    if args.zip_file: # zip file provided
        zipFile = args.zip_file[0]
        if not os.path.exists(zipFile): # make sure it exists
            print("unable to find existing file: %s" % zipFile)
            exit(1)
    else: # zip up the current working directory
        validateXmlCwd()

        # analyze XML files
        if args.inheritance:
            analyzeCwd()

        additionalDirs = ['automation'] if args.automation else []

        zipFile = createZipFromCwd(useProxy, additionalDirs, args.package_all)

    if ip:
        deployZip(zipFile, ip, args.user)

        threads = []

        # setup main thread for listening to console output
        threads.append(ConsoleListener(ip, args.t, args.report_rendezvous))

        # track node usage over time
        if args.n:
            threads.append(PollingListener(ip))

        for thread in threads:
            thread.start()

        while True:
            line = sys.stdin.readline()

            # TODO: use this command to drop into some curses screen for debugging something
    else:
        print("File saved!")

if __name__ == "__main__":
    main()
