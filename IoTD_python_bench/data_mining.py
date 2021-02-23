import requests as r
import pandas as pd
import time
import json
import sys
from csv import reader
from datetime import date
import datetime as day
from threading import *
import paho.mqtt.client as mqtt
import paho.mqtt.publish as pb
from client import subscribeStatus
from cryptography.fernet import Fernet

today = date.today()
mqtt_host=sys.argv[1]
duration= int(sys.argv[2])

symmetricKey_KIS = b'aQOQxINtlrXU_HkbJywoMxfiFMXC-OToihHK2ApIeCs='
KIS = Fernet(symmetricKey_KIS)

endtime = today - day.timedelta(days=1)
endtime = endtime.strftime("%Y%m%d")
starttime = today - day.timedelta(days = (duration+1))
starttime = starttime.strftime("%Y%m%d")
#mqtt_host="192.168.1.228"

url1="http://uoweb3.ncl.ac.uk/api/v1.1/sensors/PER_AIRMON_MESH1911150/data/json/?starttime="+starttime+"&endtime="+endtime+""
url2="http://uoweb3.ncl.ac.uk/api/v1.1/sensors/PER_AIRMON_MESH301245/data/json/?starttime="+starttime+"&endtime="+endtime+""
url3="http://uoweb3.ncl.ac.uk/api/v1.1/sensors/PER_EMOTE_1309/data/json/?starttime="+starttime+"&endtime="+endtime+""

number_of_rows = 0
df = pd.DataFrame()

def dataCollection(url):
    start = time.time()
    global df
    global number_of_rows
    response=r.get(url)
    content=[]
    values= response.json()
    for item in values['sensors']:
        variable =list(item['data'].keys())
        variableLength= len(item['data'].keys())
        for x in range(0,variableLength):
            a=variable[x]
            subitem=item['data'][a]
            for item1 in subitem:
                mydict={'Sensor':item1['Sensor Name'],'Type':item1['Variable'],'Units':item1['Units'],
                        'time':item1['Timestamp'],'Value':item1['Value'],
                        'Flag':item1['Flagged as Suspect Reading']}
                content.append(mydict)
    if(len(content)>0):
        df = df.append(content, ignore_index=True)
    end = time.time()
    #print(url)
    print(df.shape[0])
    number_of_rows= df.shape[0]
    print(end-start)

def publishResult(value,publish_topic):
    host=mqtt_host 
    port=1883
    pb.single(publish_topic, value, 0, False, host, port)

def datThread(url1,url2,url3):
    global df
    thread1=Thread(target=dataCollection,args=(url1,))
    thread2=Thread(target=dataCollection,args=(url2,))
    thread3=Thread(target=dataCollection,args=(url3,))

    thread1.start()
    thread2.start()
    thread3.start()
    thread1.join()
    thread2.join()
    thread3.join()
    df.to_csv("test1.csv",mode='w+',index=False,header= None)
    a = df.groupby(["Sensor", "Type", "Units"])["Sensor"].unique().to_frame(name="1").reset_index().drop("1", 1)
    a.to_csv("combination.csv",mode='w+',index=False,header= None)
    print(a)

datThread(url1,url2,url3)

def prepareForPublish(fileName,publish_topic):
    with open(fileName,'r') as lines:
        row_reader = reader(lines)
        for row in row_reader:
            line = ','.join(row)
            # message=KIS.encrypt((line).encode())
            message=((line).encode())
            publishResult(message,publish_topic)
    #publishResult(KIS.encrypt(("done").encode()),publish_topic)
    publishResult((("done").encode()),publish_topic)

def prepareForPublish1(fileName,publish_topic,key):
    symmetricKey_KIE = key
    KIE = Fernet(symmetricKey_KIE)
    with open(fileName,'r') as lines:
        row_reader = reader(lines)
        for row in row_reader:
            line = ','.join(row)
            message=KIE.encrypt((line).encode())
            publishResult(message,publish_topic)
    publishResult(KIE.encrypt(("done").encode()),publish_topic)

def multi_thread(key):
    thread1=Thread(target=prepareForPublish1,args=("test2.csv","usbdata_EDC1",key,))
    thread2=Thread(target=prepareForPublish1,args=("test3.csv","usbdata_EDC2",key,))

    thread1.start()
    thread2.start()
            
    thread1.join()
    thread2.join()

i=0
while(True):
    mess=subscribeStatus()
    if(mess=="usbdata"):
        prepareForPublish("combination.csv","usbdata1")
        print("SC asked for data")
    elif(mess=="abort"):
        df = pd.DataFrame()
        print("SC says abort the data and collect new data")
        datThread(url1,url2,url3)
    else:
        start3 = time.time()
        print("Received the Key")
        
        symmetricKey_KIS = b'aQOQxINtlrXU_HkbJywoMxfiFMXC-OToihHK2ApIeCs='
        KIS = Fernet(symmetricKey_KIS)
        encrypted=mess.encode()
        mess=KIS.decrypt(encrypted)
        
        if i==0:
            df[0:500].to_csv("test2.csv",mode='w+',index=False,header= None)
            df[500:1000].to_csv("test3.csv",mode='w+',index=False,header= None)
            publishResult(str(1000),"decrypt_time1")
            publishResult(str(1000),"decrypt_time2")
            multi_thread(mess)
        
            print("send to EDC")
            i=i+1
        elif i==1:
            df[0:1000].to_csv("test2.csv",mode='w+',index=False,header= None)
            df[1000:2000].to_csv("test3.csv",mode='w+',index=False,header= None)
            publishResult(str(2000),"decrypt_time1")
            publishResult(str(2000),"decrypt_time2")
            multi_thread(mess)
            #publishResult(str(2000),"decrypt_time")
            print("send to EDC")
            i=i+1
        elif i==2:
            df[0:2500].to_csv("test2.csv",mode='w+',index=False,header= None)
            df[2500:5000].to_csv("test3.csv",mode='w+',index=False,header= None)
            publishResult(str(5000),"decrypt_time1")
            publishResult(str(5000),"decrypt_time2")
            multi_thread(mess)
            #publishResult(str(5000),"decrypt_time")
            print("send to EDC")
            i=i+1
        elif i==3:
            df[0:5000].to_csv("test2.csv",mode='w+',index=False,header= None)
            df[5000:10000].to_csv("test3.csv",mode='w+',index=False,header= None)
            publishResult(str(10000),"decrypt_time1")
            publishResult(str(10000),"decrypt_time2")
            multi_thread(mess)
            #publishResult(str(10000),"decrypt_time")
            print("send to EDC")
            i=i+1
        elif i==4:
            df[0:10000].to_csv("test2.csv",mode='w+',index=False,header= None)
            df[10000:20000].to_csv("test3.csv",mode='w+',index=False,header= None)
            publishResult(str(20000),"decrypt_time1")
            publishResult(str(20000),"decrypt_time2")
            multi_thread(mess)
            #publishResult(str(20000),"decrypt_time")
            print("send to EDC")
            i=i+1
        elif i==5:
            df[0:20000].to_csv("test2.csv",mode='w+',index=False,header= None)
            df[20000:40000].to_csv("test3.csv",mode='w+',index=False,header= None)
            publishResult(str(40000),"decrypt_time1")
            publishResult(str(40000),"decrypt_time2")
            multi_thread(mess)
            #publishResult(str(40000),"decrypt_time")
            print("send to EDC")
            i=0
        
        end3 = time.time()
        print(end3-start3)
        
        publishResult(str(end3-start3),"encrypt_time")
        
        df = pd.DataFrame()
        datThread(url1,url2,url3)