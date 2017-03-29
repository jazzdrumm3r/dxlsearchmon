# This code provides a menu of option to allow viewing of DXL events,
# and perform basic ePO and MAR searches.  ePO searches require that 
# the ePO python service is running.


import logging
import os
import sys
import time
import json

from dxlclient.callbacks import EventCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient, ReputationChangeCallback
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, \
    CertProvider, CertEnterpriseAttrib, RepChangeEventProp
from dxlepoclient import EpoClient, OutputFormat
from dxlmarclient import MarClient, ResultConstants, ProjectionConstants, \
    ConditionConstants, SortConstants, OperatorConstants

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logger = logging.getLogger(__name__)

# The ePO unique identifier
EPO_UNIQUE_ID = "epo1"
# The size of each page for MAR searches
PAGE_SIZE = 20
# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Set topics to fire Events on
EVENT_TOPIC_2= "/mcafee/event/tie/file/firstinstance"
EVENT_TOPIC_3 = "/mcafee/event/atd/file/report"
EVENT_TOPIC_4 = "/mcafee/service/epo/remote/epo1"

#configure menu
menu = {}
menu['1']="Monitor and Present TIE File Reputation Changes" 
menu['2']="Monitor TIE First Instance Events"
menu['3']="Monitor and Present DXL ATD File Reports"
menu['4']="Monitor ePO Remote Service Activity"
menu['5']="Query MAR by IP Address and show host processes"
menu['6']="Query EPO for text"
menu['7']="Exit"

# Initialize Dictionary Search
#PyObject repkey, rep_value;
#Py_ssize_t pos = 0;

# Get a given data from a dictionary with position provided as a list
def getFromDict(dataDict, mapList):    
    for k in mapList: dataDict = dataDict[k]
    return dataDict

#perform ePO search
def epo_search(epotext):
    # Create the ePO client
    epo_client = EpoClient(client, EPO_UNIQUE_ID)
    # Run the system find command
    res = epo_client.run_command("system.find",
                                 {"searchText": epotext},
                                 output_format=OutputFormat.JSON)
    # Load find result into dictionary
    res_dict = json.loads(res, encoding='utf-8')
    # Display the results
    print json.dumps(res_dict, sort_keys=True, indent=4, separators=(',', ': '))
    return
#perform Mar Search
def mar_search(HOST_IP):
    # Create the McAfee Active Response (MAR) client
    marclient = MarClient(client)

    # Start the search
    results_context = \
        marclient.search(
            projections=[{
                ProjectionConstants.NAME: "Processes",
            }],
            conditions={
                ConditionConstants.OR: [{
                    ConditionConstants.AND: [{
                        ConditionConstants.COND_NAME: "HostInfo",
                        ConditionConstants.COND_OUTPUT: "ip_address",
                        ConditionConstants.COND_OP: OperatorConstants.EQUALS,
                        ConditionConstants.COND_VALUE: HOST_IP
                    }]
                }]
            }
        )

    # Iterate the results of the search in pages
    if results_context.has_results:
        for index in range(0, results_context.result_count, PAGE_SIZE):
            # Retrieve the next page of results (sort by process name, ascending)
            results = results_context.get_results(index, PAGE_SIZE,
                                                  sort_by="Processes|name",
                                                  sort_direction=SortConstants.ASC)
            # Display items in the current page
            print "Page: " + str((index/PAGE_SIZE)+1)
            for item in results[ResultConstants.ITEMS]:
                print "    " + item[ResultConstants.ITEM_OUTPUT]["Processes|name"]
            dummy_text = raw_input("Press Enter for Next Page")
    return

#Callback to handle TIE reputation change event
class MyReputationChangeCallback(ReputationChangeCallback):
    def on_reputation_change(self, rep_change_dict, original_event):
        # Display the DXL topic that the event was received on
        print ("\n\n\n=========================================================================")
        localtime = time.asctime( time.localtime(time.time()) )
        print (localtime + " Reputation change")
        print ("DXLTopic: " + original_event.destination_topic)
        maplist = ["hashes", "md5"]
        filehash = getFromDict(rep_change_dict,maplist)
        print ("File MD5: " + filehash)
        maplist = ["hashes", "sha1"]
        filehash = getFromDict(rep_change_dict,maplist)
        print ("File SHA1: " + filehash)
        maplist = ["hashes", "sha256"]
        filehash = getFromDict(rep_change_dict,maplist)
        print ("File SHA256: " + filehash) 
        oldgtifrep = rep_change_dict['oldReputations'][1]['trustLevel']
        newgtifrep = rep_change_dict['newReputations'][1]['trustLevel']
        oldentfrep = rep_change_dict['oldReputations'][3]['trustLevel']
        newentfrep = rep_change_dict['newReputations'][3]['trustLevel']
        oldatdfrep = rep_change_dict['oldReputations'][5]['trustLevel']
        newatdfrep = rep_change_dict['newReputations'][5]['trustLevel']
        print "GTI Old Rep: %s.  New: %s" % (oldgtifrep, newgtifrep)
        print "Ent Old Rep: %s.  New: %s" % (oldentfrep, newentfrep)
        print "ATD Old Rep: %s.  New: %s" % (oldatdfrep, newatdfrep)
        print "===============================================================================\n\n"

#Callback to log events
class MyEventCallback(EventCallback):
    def on_event(self, event):
        # Extract information from Event payload, in this sample we expect it is UTF-8 encoded
        logger.info("Event Subscriber - Event received:\n   Topic: %s\n   Payload: %s", 
                            event.destination_topic, event.payload.decode())

# Main loop
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()

    # Create the McAfee Threat Intelligence Exchange (TIE) client
    tie_client = TieClient(client)


    # Present User menu and run option
    while True: 
        options=menu.keys()
        options.sort()
        print("\n\n\n\n\n==== DXL Monitor & Search Tool ====")
        for entry in options: 
          print entry, menu[entry]
        selection=raw_input("Please Select:") 
        if selection =='1': 
            # Create reputation change callback
            rep_change_callback = MyReputationChangeCallback()
            tie_client.add_file_reputation_change_callback(rep_change_callback)
            tie_client.add_certificate_reputation_change_callback(rep_change_callback)
            print "Listening for TIE Reputation Changes.  Press <Control-C> to exit."
            while True:
                time.sleep(60)
        elif selection == '2': 
            logger.info("Adding Event callback function to Topic: %s", EVENT_TOPIC_2)
            client.add_event_callback(EVENT_TOPIC_2, MyEventCallback())
        elif selection == '3':
            logger.info("Adding Event callback function to Topic: %s", EVENT_TOPIC_3)
            client.add_event_callback(EVENT_TOPIC_3, MyEventCallback())
        elif selection == '4': 
            logger.info("Adding Event callback function to Topic: %s", EVENT_TOPIC_4)
            client.add_event_callback(EVENT_TOPIC_4, MyEventCallback())
        elif selection == '5': 
            HOST_IP = raw_input ("Enter host IP address to search:  ")
            mar_search(HOST_IP)
        elif selection == '6': 
            epo_search_text = raw_input("Enter ePO search text: ")
            epo_search(epo_search_text)
        elif selection == '7': 
            break
        else: 
           print "Unknown Option Selected!" 

  

