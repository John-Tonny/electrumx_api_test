#!/usr/bin/python3

import json

from websocket import create_connection

def getMessage(method, params):
    msg = {"jsonrpc": "2.0", 
           "method": method, 
           "id": 1,
           "params":params
           }
    return json.dumps(msg)

ws = create_connection("ws://localhost:50003")
print("Sending 'Hello, World'...")
params=[]
method='blockchain.block.headers'
params.append(100)
params.append(1)
msg=getMessage(method,params)
ws.send(msg)
print("Sent")
print("Reeiving...")
result =  ws.recv()
print("Received '%s'" % result)
ws.close()

