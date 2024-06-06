import argparse
import os
import sys
from scapy.all import *
from pyspark import *
from pyspark.context import SparkContext
import pandas as pd
from keras.models import Sequential
from keras.layers import Dense
import yaml
import keras
import ansible.inventory
from ansible_playbook_runner import Runner

def processPcap(fileName):
    #rint('Opening {}...'.format(fileName))

    count = 0
    #tuple of general packets
    tuplePKt=[]
    #tuple of SYN packets
    tupleSyn=[]
    #tuple of SYN-ACK packets
    tupleSynAck=[]
    #tuple of ACK packets
    tupleAck=[]
    #Victim server address
    clientAddress= '172.16.1.3'
    #Data list to save to csv file
    data=[[]]
    #number of incoming packets
    nbOfInPkt=0
    #Time between 2 consecutive forward-direction pkts list
    time=[]
    #number of bytes
    nbOfBytes=0
    for (pktData, pktMetadata,) in RawPcapReader(fileName):
        count += 1
        
        etherPkt = Ether(pktData)
        if 'type' not in etherPkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if etherPkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ipPkt = etherPkt[IP]
        #if the packet is from server victim, it is outgoing packet
        if ipPkt.src!=clientAddress:
           nbOfInPkt+=1
           if nbOfInPkt==1:
              firstPktTimeStamp=ipPkt.time#(pktMetadata.tshigh << 32) | pkt_metadata.tslow
              previousPktTimeStamp=firstPktTimeStamp
              continue
           currentPktTimeStamp=ipPkt.time#(pktMetadata.tshigh << 32) | pkt_metadata.tslow
           timeBw2Pkt=currentPktTimeStamp-previousPktTimeStamp
           previousPktTimeStamp=currentPktTimeStamp
           time.append(timeBw2Pkt)
           nbOfBytes+=ipPkt.len
    data[0].append(nbOfInPkt)
    data[0].append(nbOfBytes)
    #print(len(time))
    # Summary of time between 2 consecutive packets in the list
    sumOfTimeBw2Pkt=0
    for a in time:
        sumOfTimeBw2Pkt+=a
    #print(sumOfTimeBw2Pkt)
    #Calculate average time between 2 consecutive packets
    avrTimeBw2Pkt=sumOfTimeBw2Pkt/len(time)
    data[0].append(avrTimeBw2Pkt)
    return data, ipPkt.src

def flowDetector(data):
    #load ANN model
    model = keras.models.load_model('models/model_flow.h5')
    #predict a flow:
    flow_type = (model.predict(data)>0.5).astype(int)

    return flow_type

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    fileName = args.pcap
    if not os.path.isfile(fileName):
        print('"{}" does not exist'.format(fileName), file=sys.stderr)
        sys.exit(-1)
    #load scaler
    scaler=joblib.load('models/flow_scaler.gz')
    #Extract feature of a flow from a pcap file
    flowFeatures, ipAddress = processPcap(fileName)
    #Normalizing the collected data
    flowFeatures = scaler.transform(flowFeatures)
    # Detect abnormal flow
    isAbnormalFlow = flowDetector(flowFeatures)

    if isAbnormalFlow:
        print('"{}" is an attacker'.format(ipAddress))
    #update Ip address of abnormal flow to firewall
        print('"Blocking {}..."'.format(ipAddress))
        with open(r'./vars.yaml') as f:
            doc = yaml.full_load(f)

        doc['ip_address'] = ipAddress
        with open('./vars.yaml', 'w') as f:
            yaml.dump(doc, f)
        Runner(['hosts'], "update_blacklist_iptable_playbook.yaml").run()
        print("Blocked successuly")
    else :
        print('"{}" is a normal user'.format(ipAddress))
