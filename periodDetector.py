import argparse
import os
import sys
from scapy.all import *
from pyspark import *
from pyspark.context import SparkContext
import pandas as pd
import keras
import yaml
import joblib

def processPcap(fileName):
    #print('Opening {}...'.format(fileName))

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
    serverAddress= '172.16.1.3'
    #Data list to save to csv file
    data=[[]]
    #number of outgoing packets
    nbOfOutPkt=0
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
        #if the packet is form server victim, it is outgoing packet
        if ipPkt.src==serverAddress:
           nbOfOutPkt+=1

        if ipPkt.proto == 6: #TCP packets
           tcpPkt=ipPkt[TCP]
           tpTCP=(ipPkt.src,ipPkt.dst,tcpPkt.sport,tcpPkt.dport,"TCP")
           tuplePKt.append(tpTCP)
           if 'S' in str(tcpPkt.flags) and 'A' not in str(tcpPkt.flags):
              tpTcpSyn=(ipPkt.src,ipPkt.dst,tcpPkt.sport,tcpPkt.dport)
              tupleSyn.append(tpTcpSyn)
           if 'S' in str(tcpPkt.flags) and 'A' in str(tcpPkt.flags):
              tpTcpSynAck=(ipPkt.src,ipPkt.dst,tcpPkt.sport,tcpPkt.dport)
              tupleSynAck.append(tpTcpSynAck)
           if 'A' in str(tcpPkt.flags) and 'S' not in str(tcpPkt.flags):
              tpTcpAck=(ipPkt.src,ipPkt.dst,tcpPkt.sport,tcpPkt.dport)
              tupleAck.append(tpTcpAck)
        if ipPkt.proto == 17: #UDP packets
           udpPkt=ipPkt[UDP]
           tpUDP=(ipPkt.src,ipPkt.dst,udpPkt.sport,udpPkt.dport,"UDP")
           tuplePKt.append(tpUDP)
        if ipPkt.proto == 1: #ICMP packets
           tpICMP=(ipPkt.src,ipPkt.dst,"ICMP")
           tuplePKt.append(tpICMP)
    sc=SparkContext("local", "pcap Reader")
    #print(tuplePKt)

    #Calculate Average length of flow
    countPkt = sc.parallelize(tuplePKt, numSlices=3).countByValue().values()      
    #print(countPkt)
    countPktMap=sc.parallelize(countPkt, numSlices=3).map(lambda x:(x,1))
    countPktReduce=sc.parallelize(list(countPktMap.collect()), numSlices=3).reduce(lambda a,b:(a[0]+b[0],a[1]+b[1]))
    #print(countPktReduce)
    avrLengthFlow=0
    avrLengthFlow=countPktReduce[0]/countPktReduce[1]
    #print(avrLengthFlow)
    data[0].append(avrLengthFlow)
    #Caculate percentage of correlative flows
    nbOfCorrFlows=0
    # ICMP flows
    setofFlows = sc.parallelize(tuplePKt,numSlices=3).countByValue().keys()
    nbOfCorrIcmpFlows = 0
    for a in setofFlows:
        for b in setofFlows:
            if a[0] == b[1] and a[1]==b[0] and a[2]=="ICMP" and b[2]=="ICMP":
                nbOfCorrIcmpFlows=nbOfCorrIcmpFlows+1
        #        print(a,b)
    #print(nbOfCorrIcmpFlows)
    # TCP flows
    setofSynFl=sc.parallelize(tupleSyn,numSlices=3).countByValue().keys()
    #print(setofSynFl)
    setofSynAckFl=sc.parallelize(tupleSynAck,numSlices=3).countByValue().keys()
    setofAckFl=list(sc.parallelize(tupleAck,numSlices=3).countByValue().keys())
    nbOfCorrTcpFlows = 0
    #for a in setofSynFl:
    #    for b in setofSynAckFl:
    #        for c in setofAckFl:
    #            if a[0]==b[1] and a[0]==c[0] and a[1]==b[0] and a[1]==c[1]: #and a[2]==b[3] and a[2]==c[2] and a[3]==b[2] and a[3]==c[3]:
    #               setofAckFl.remove(c)#we need to remove this flow to distigush the correlative flows in  connection validation time and normal time
    #               nbOfCorrTcpFlows=nbOfCorrTcpFlows+1
                   #print(setofAckFl)
    #nbOfCorrTcpFlows=nbOfCorrTcpFlows*2 #we need to mutiply to calculate the sum of correlative tcp flows
    for a in setofAckFl:
        for b in setofAckFl:
            if a[0]==b[1] and a[1]==b[0] and a[2]==b[3] and a[3]==b[2]:
               nbOfCorrTcpFlows=nbOfCorrTcpFlows+1
    nbOfCorrFlows=0
    nbOfCorrFlows=(nbOfCorrIcmpFlows+nbOfCorrTcpFlows)/countPktReduce[1]
    data[0].append(nbOfCorrFlows)
    # Calculate one direction gerating speed
    odgs=0
    odgs=(countPktReduce[1]-nbOfCorrFlows)/5
    data[0].append(odgs)
    #Calculate ratio of Incoming and Outgoing packets
    nbInPkt=0
    nbInPkt=(count-nbOfOutPkt)
    data[0].append(nbInPkt)
    return data

def periodDetector(data):
    #load ANN model
    model = keras.models.load_model('models/period_model.h5')
    #predict a period:
    period_type = (model.predict(data)>0.5).astype(int)

    return period_type

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
    scaler=joblib.load('models/period_scaler.gz')
    #Extract feature of a period from a pcap file
    periodFeatures = processPcap(fileName)
    #Normalizing the collected data
    periodFeatures = scaler.transform(periodFeatures)
    # Detect abnormal period
    isAbnormalPeriod = periodDetector(periodFeatures)
    #print("prediction results:" ,isAbnormalPeriod)
    #Return 1 if there is an attack. If else return 0
    if isAbnormalPeriod == 1:
        print("1")