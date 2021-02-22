import paho.mqtt.subscribe as sub
import asymcrypt
import paho.mqtt.publish as pb
import datetime as dtm
import sys
import logging
import time

import socket
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind((socket.gethostname(),9003))
s.listen()

HOST = sys.argv[1]
PORT = 1883

def print_received_message_mqtt(msg):
    print("Message received. Payload: {}".format(str(msg.payload)))

def on_message_print(client, userdata, msg):
    if msg.topic == "sensor_data_req":
        # print_received_message_mqtt(msg)
        mess=msg.payload.decode("utf-8")
        clientsocket,address = s.accept()
        clientsocket.send(bytes(mess,"utf-8"))
        # pb.single(TOPIC, key, 0, False, CONTAINER_MQTT_HOST, PORT)
    elif msg.topic == "sensor_sym_key":
        # print_received_message_mqtt(msg)
        mess=msg.payload.decode("utf-8")
        clientsocket,address = s.accept()
        clientsocket.send(bytes(mess,"utf-8"))

logging.info("Subscription started.")
sub.callback(on_message_print, ["sensor_data_req","sensor_sym_key"], hostname=HOST, port=PORT)