import argparse
import os
import sys
from scapy.all import *
from pyspark import *
from pyspark.context import SparkContext
import pandas as pd
def processPcap(fileName):
    print('Opening {}...'.format(fileName))

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
    clientAddress= '172.16.1.4'
    #Data list to save to csv file
    data=[]
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
        #if the packet is form server victim, it is outgoing packet
        if ipPkt.src==clientAddress:
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
    data.append(nbOfInPkt)
    data.append(nbOfBytes)
    print(len(time))
    # Summary of time between 2 consecutive packets in the list
    sumOfTimeBw2Pkt=0
    for a in time:
        sumOfTimeBw2Pkt+=a
    print(sumOfTimeBw2Pkt)
    #Calculate average time between 2 consecutive packets
    avrTimeBw2Pkt=sumOfTimeBw2Pkt/len(time)
    data.append(avrTimeBw2Pkt)
    #Open csv file and save data to the file
    if(os.path.exists('datasetLSTM.csv')):
        df=pd.read_csv('datasetLSTM.csv')
    else:
        columns=["Number Packet", "Number Bytes", "Time between 2 packets"]#, "CPU usage", "Memory usage", "Network bandwidth", "Label"]
        df=pd.DataFrame(columns=columns)
        df.to_csv('datasetLSTM.csv', encoding='utf-8', index=False)
    num=len(df)+1
    df.loc[num]=data
    #df.iloc[num-1,7]=1
    df.to_csv('datasetLSTM.csv', encoding='utf-8', index=False)
    print('{} contains {} packets'.format(fileName, count))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    fileName = args.pcap
    if not os.path.isfile(fileName):
        print('"{}" does not exist'.format(fileName), file=sys.stderr)
        sys.exit(-1)

    processPcap(fileName)
    sys.exit(0)