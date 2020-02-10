#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import re
import socket
import ssl
import sys
import threading
import time
import traceback
import json
import requests
import bitcoin 

from hashlib import sha256

import argparse

#ca_path = requests.certs.where()
ca_path = '/root/myapi/cacert.pem'

import util
import x509
import pem
import binascii
import base58
#from electrum_dash.version import ELECTRUM_VERSION, PROTOCOL_VERSION

def parse_json(message):
    # TODO: check \r\n pattern
    n = message.find(b'\n')
    if n==-1:
        return None, message
    try:
        j = json.loads(message[0:n].decode('utf8'))
    except:
        j = None
    return j, message[n+1:]


class SocketPipe:
    def __init__(self, socket):
        self.socket = socket
        self.message = b''
        self.set_timeout(1.5)
        self.recv_time = time.time()
        self.msg = ''
        
    def addMsg(self,*args):
        self.msg=args

    def set_timeout(self, t):
        self.socket.settimeout(t)

    def idle_time(self):
        return time.time() - self.recv_time
    
    def send_requests(self):
        '''Sends queued requests.  Returns False on failure.'''
        make_dict = lambda m, p, i: {'method': m, 'params': p, 'id': i}
        wire_requests = []
        wire_requests.append(self.msg)
        try:
            self.send_all([make_dict(*r) for r in wire_requests])
        except BaseException as e:
            #self.print_error("pipe send error:", e)
            return False
        return True
    
    def get(self):
        while True:
            response, self.message = parse_json(self.message)
            if response is not None:                
                return response
            try:
                data = self.socket.recv(1024)
            except socket.timeout:
                raise "timeout"
            except ssl.SSLError:
                raise timeout
            except socket.error as err:
                if err.errno == 60:
                    raise "timeout"
                elif err.errno in [11, 35, 10035]:
                    print_error("socket errno %d (resource temporarily unavailable)"% err.errno)
                    time.sleep(0.2)
                    raise "timeout"
                else:
                    print_error("pipe: socket error", err)
                    data = b''
            except:
                traceback.print_exc(file=sys.stderr)
                data = b''

            if not data:  # Connection closed remotely
                return None
            self.message += data
            self.recv_time = time.time()
        return self.message

    def send(self, request):
        out = json.dumps(request) + '\n'
        out = out.encode('utf8')
        self._send(out)

    def send_all(self, requests):
        out = b''.join(map(lambda x: (json.dumps(x) + '\n').encode('utf8'), requests))
        self._send(out)

    def _send(self, out):
        while out:
            try:
                sent = self.socket.send(out)
                out = out[sent:]
            except ssl.SSLError as e:
                print_error("SSLError:", e)
                time.sleep(0.1)
                continue

class TcpConnection(util.PrintError):
    verbosity_filter = 'i'

    def __init__(self,config_path):
        self.config_path = config_path
        self.host= '116.85.13.95'  #'localhost'
        self.port=50002
        self.host = str(self.host)
        self.port = int(self.port)
        self.use_ssl = True
        self.config_path = config_path

    def get_simple_socket(self):
        try:
            ll = socket.getaddrinfo(self.host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            self.print_error("cannot resolve hostname")
            return
        e = None
        for res in ll:
            try:
                s = socket.socket(res[0], socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect(res[4])
                s.settimeout(2)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                return s
            except BaseException as _e:
                e = _e
                continue
        else:
            self.print_error("failed to connect", str(e))
            pass

    @staticmethod
    def get_ssl_context(cert_reqs, ca_certs):
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_certs)
        context.check_hostname = False
        context.verify_mode = cert_reqs

        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1

        return context

    def get_socket(self):
        if self.use_ssl:
            cert_path = os.path.join(self.config_path, 'certs', self.host)
            if not os.path.exists(cert_path):
                is_new = True
                s = self.get_simple_socket()
                if s is None:
                    return
                # try with CA first
                try:
                    context = self.get_ssl_context(cert_reqs=ssl.CERT_REQUIRED, ca_certs=ca_path)
                    s = context.wrap_socket(s, do_handshake_on_connect=True)
                except ssl.SSLError as e:
                    self.print_error(e)
                except:
                    return
                else:
                    try:
                        peer_cert = s.getpeercert()
                    except OSError:
                        return
                    if self.check_host_name(peer_cert, self.host):
                        self.print_error("SSL certificate signed by CA")
                        return s
                # get server certificate.
                # Do not use ssl.get_server_certificate because it does not work with proxy
                s = self.get_simple_socket()
                if s is None:
                    return
                try:
                    context = self.get_ssl_context(cert_reqs=ssl.CERT_NONE, ca_certs=None)
                    s = context.wrap_socket(s)
                except ssl.SSLError as e:
                    self.print_error("SSL error retrieving SSL certificate:", e)
                    return
                except:
                    return

                try:
                    dercert = s.getpeercert(True)
                except OSError:
                    return
                s.close()
                cert = ssl.DER_cert_to_PEM_cert(dercert)
                # workaround android bug
                cert = re.sub("([^\n])-----END CERTIFICATE-----","\\1\n-----END CERTIFICATE-----",cert)
                temporary_path = cert_path + '.temp'
                util.assert_datadir_available(self.config_path)
                with open(temporary_path, "w", encoding='utf-8') as f:
                    f.write(cert)
                    f.flush()
                    os.fsync(f.fileno())
            else:
                is_new = False

        s = self.get_simple_socket()
        if s is None:
            return

        if self.use_ssl:
            try:
                context = self.get_ssl_context(cert_reqs=ssl.CERT_REQUIRED,
                                               ca_certs=(temporary_path if is_new else cert_path))
                s = context.wrap_socket(s, do_handshake_on_connect=True)
            except socket.timeout:
                self.print_error('timeout')
                return
            except ssl.SSLError as e:
                self.print_error("SSL error:", e)
                if e.errno != 1:
                    return
                if is_new:
                    rej = cert_path + '.rej'
                    if os.path.exists(rej):
                        os.unlink(rej)
                    os.rename(temporary_path, rej)
                else:
                    util.assert_datadir_available(self.config_path)
                    with open(cert_path, encoding='utf-8') as f:
                        cert = f.read()
                    try:
                        b = pem.dePem(cert, 'CERTIFICATE')
                        x = x509.X509(b)
                    except:
                        traceback.print_exc(file=sys.stderr)
                        self.print_error("wrong certificate")
                        return
                    try:
                        x.check_date()
                    except:
                        self.print_error("certificate has expired:", cert_path)
                        os.unlink(cert_path)
                        return
                    self.print_error("wrong certificate")
                if e.errno == 104:
                    return
                return
            except BaseException as e:
                self.print_error(e)
                traceback.print_exc(file=sys.stderr)
                return

            if is_new:
                self.print_error("saving certificate")
                os.rename(temporary_path, cert_path)

        return s
    
    def send_requests(self):
        '''Sends queued requests.  Returns False on failure.'''
        self.last_send = time.time()
        make_dict = lambda m, p, i: {'method': m, 'params': p, 'id': i}
        n = self.num_requests()
        wire_requests = self.unsent_requests[0:n]
        try:
            self.pipe.send_all([make_dict(*r) for r in wire_requests])
        except BaseException as e:
            self.print_error("pipe send error:", e)
            return False
        self.unsent_requests = self.unsent_requests[n:]
        for request in wire_requests:
            if self.debug:
                self.print_error("-->", request)
            self.unanswered_requests[request[2]] = request
        return True

def check_cert(host, cert):
    try:
        b = pem.dePem(cert, 'CERTIFICATE')
        x = x509.X509(b)
    except:
        traceback.print_exc(file=sys.stdout)
        return

    try:
        x.check_date()
        expired = False
    except:
        expired = True

    m = "host: %s\n"%host
    m += "has_expired: %s\n"% expired
    util.print_msg(m)


def getBlockheaders(socketPipe):
    params=[]
    method='blockchain.block.headers'
    params.append(1)
    params.append(2)
    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    headers = socketPipe.get()
    print("headers:",headers) 
    print("headers len:",len(headers["result"]["hex"]))

def getEstimatefee(socketPipe):
    params=[]
    method='blockchain.estimatefee'
    params.append(12)
    
    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("estimate:",socketPipe.get())    
    
def getBlockHeaderSubscribe(socketPipe):
    params=[]
    method='blockchain.headers.subscribe'
        
    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("headerSubscribe:",socketPipe.get())        

def getRelayfee(socketPipe):
    params=[]
    method='blockchain.relayfee'

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("relay:",socketPipe.get())        

def getBalance(socketPipe):
    params=[]
    method='blockchain.scripthash.get_balance'
    
    x = sha256()
    x.update(bytes.fromhex("76a914ff3b989aee2d88c842a621cff37f8d3ff76b3a4b88ac"))
    y=x.hexdigest()
    scriptHash=bytes(reversed(bytes.fromhex(y))).hex()
    #print(scriptHash)
    params.append(scriptHash)

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("balance:",socketPipe.get())        

def getHistory(socketPipe):
    params=[]
    method='blockchain.scripthash.get_history'

    x = sha256()
    x.update(bytes.fromhex('76a914ff3b989aee2d88c842a621cff37f8d3ff76b3a4b88ac'))
    y=x.hexdigest()
    scriptHash=bytes(reversed(bytes.fromhex(y))).hex()
    #print(scriptHash)
    params.append(scriptHash)

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("history:",socketPipe.get())        

def getMempool(socketPipe):
    params=[]
    method='blockchain.scripthash.get_mempool'

    x = sha256()
    x.update(bytes.fromhex("76a914ff3b989aee2d88c842a621cff37f8d3ff76b3a4b88ac"))
    y=x.hexdigest()
    scriptHash=bytes(reversed(bytes.fromhex(y))).hex()
    #print(scriptHash)
    params.append(scriptHash)

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("mempool:",socketPipe.get())        

def getListUnspent(socketPipe):
    params=[]
    method='blockchain.scripthash.listunspent'

    x = sha256()
    x.update(bytes.fromhex('76a914ff3b989aee2d88c842a621cff37f8d3ff76b3a4b88ac'))  #"Vcp85KYRxf9UX3wfDJUMKJKt1XhxUH6MYBB"
    y=x.hexdigest()
    scriptHash=bytes(reversed(bytes.fromhex(y))).hex()
    #print(scriptHash)
    params.append(scriptHash)

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("listunspent:",socketPipe.get())        

def getScripthashSubscribe(socketPipe):
    params=[]
    method='blockchain.scripthash.subscribe'

    x = sha256()
    x.update(bytes.fromhex('76a914ff3b989aee2d88c842a621cff37f8d3ff76b3a4b88ac'))
    y=x.hexdigest()
    scriptHash=bytes(reversed(bytes.fromhex(y))).hex()
    #print(scriptHash)
    params.append(scriptHash)

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("scripthashSubscribe:",socketPipe.get())   
    
def getUtxos(socketPipe):
    params=[]
    method='blockchain.scripthash.utxos'  

    x = sha256()
    x.update(bytes.fromhex('76a91465c4a17e0bf327e48ecbf27c71364469c771288d88ac'))  #PhCswc7JGMo3nfVSf5Xdv8wEJDpCLyJbAG
    y=x.hexdigest()
    scriptHash=bytes(reversed(bytes.fromhex(y))).hex()
    #print(scriptHash)
    params.append(scriptHash)
    params.append(10000)

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("utxos:",socketPipe.get())   
    
def getBroadcast(socketPipe):
    params=[]
    method='blockchain.transaction.broadcast'

    x = sha256()
    x.update(bytes.fromhex('76a91465c4a17e0bf327e48ecbf27c71364469c771288d88ac'))
    y=x.hexdigest()
    scriptHash=bytes(reversed(bytes.fromhex(y))).hex()
    #print(scriptHash)
    params.append(scriptHash)

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print(socketPipe.get())
    
def getTransaction(socketPipe):
    params=[]
    method='blockchain.transaction.get'

    params.append('a60bd11f71c13da8f31b16950415b5a1303bb2a7c67fc4285f1b1c69c4664e3e')
    params.append(False)

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("transaction_get:",socketPipe.get())   
    
def getMerklet(socketPipe):
    params=[]
    method='blockchain.transaction.get_merkle'

    params.append('a60bd11f71c13da8f31b16950415b5a1303bb2a7c67fc4285f1b1c69c4664e3e')
    params.append(10000)

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("transaction_merklet:",socketPipe.get())   
    
def getIdFromPos(socketPipe):
    params=[]
    method='blockchain.transaction.id_from_pos'

    params.append(10000)
    params.append(5)
    params.append(False)

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("IdFromPos",socketPipe.get())   
    
def getMempoolChange(socketPipe):
    params=[]
    method=''

    x = sha256()
    x.update(bytes.fromhex('76a91465c4a17e0bf327e48ecbf27c71364469c771288d88ac'))
    y=x.hexdigest()
    scriptHash=bytes(reversed(bytes.fromhex(y))).hex()
    #print(scriptHash)
    params.append(scriptHash)

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("mempoolChange:",socketPipe.get())   
    
def getHisogram(socketPipe):
    params=[]
    method='mempool.get_fee_histogram'


    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("fee_hisogram:",socketPipe.get())   
    
def getPeersAdd(socketPipe):
    params=[]
    method='server.add_peer'

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("peersadd",socketPipe.get())   
    
def getBanner(socketPipe):
    params=[]
    method='server.banner'

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("banner:",socketPipe.get())   
    
def getFeature(socketPipe):
    params=[]
    method='server.features'

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("feature:",socketPipe.get())   

def getPeersSubscribe(socketPipe):
    params=[]
    method='server.peers.subscribe'

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("peersSubscribe:",socketPipe.get())   

def getPing(socketPipe):
    params=[]
    method='server.ping'

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("ping:",socketPipe.get())   
    
def getVersion(socketPipe):
    params=[]
    method='server.version'
    params.append('myclient')
    params.append('1.4')

    socketPipe.addMsg(method, params, id)
    socketPipe.send_requests()
    print("version:",socketPipe.get())

def AddressToScriptHash(address):
    myaddress = base58.b58decode_check(address)  
    pubkey=binascii.hexlify(myaddress)
    assert len(pubkey)==42
    middle=pubkey[2:]
    headers=bytes(b'76a914')
    tails=bytes(b'88ac')
    return headers+middle+tails

if __name__ == "__main__":
    from sys import argv
    
    #if(len(argv)!=4):
    #    print("params error")
    #    return 
    
    print("pubkey:",AddressToScriptHash(b'PhCswc7JGMo3nfVSf5Xdv8wEJDpCLyJbAG'))
    
    #sh=bitcoin.address_to_scripthash('XtbiRfL3wBvhBkZtRdcuDnk5tMrNG4sLuk')
    #print(sh)
    
    params = []
    id=0
    method=argv[1]
    for i in range(len(argv)-2):
        params.append(argv[i+2])
        
    client=TcpConnection('/root/myapi')
    interface=client.get_socket()
    socketPipe=SocketPipe(interface)
    
    #socketPipe.addMsg(method, params, id)
    #socketPipe.send_requests()
    #print(socketPipe.get())
    
    getBlockheaders(socketPipe)
    getEstimatefee(socketPipe)
    getBlockHeaderSubscribe(socketPipe)
    getRelayfee(socketPipe)
    getBalance(socketPipe)
    getHistory(socketPipe)
    getMempool(socketPipe)
    getListUnspent(socketPipe)
    
    getScripthashSubscribe(socketPipe)
    #getUtxos(socketPipe)
    getTransaction(socketPipe)
    getMerklet(socketPipe)
    #getMempoolChange(socketPipe)
    getIdFromPos(socketPipe)
    getHisogram(socketPipe)
    getBanner(socketPipe)
    getFeature(socketPipe)
    getPeersSubscribe(socketPipe)
    getPing(socketPipe)
    getVersion(socketPipe)
    pass


'''
'blockchain.block.header': self.block_header,
            'blockchain.block.headers': self.block_headers,
            'blockchain.estimatefee': self.estimatefee,
            'blockchain.headers.subscribe': self.headers_subscribe,
            'blockchain.relayfee': self.relayfee,
            'blockchain.scripthash.get_balance': self.scripthash_get_balance,
            'blockchain.scripthash.get_history': self.scripthash_get_history,
            'blockchain.scripthash.get_mempool': self.scripthash_get_mempool,
            'blockchain.scripthash.listunspent': self.scripthash_listunspent,
            'blockchain.scripthash.subscribe': self.scripthash_subscribe,
            'blockchain.transaction.broadcast': self.transaction_broadcast,
            'blockchain.transaction.get': self.transaction_get,
            'blockchain.transaction.get_merkle': self.transaction_merkle,
            'blockchain.transaction.id_from_pos': self.transaction_id_from_pos,
            'mempool.get_fee_histogram': self.mempool.compact_fee_histogram,
            'server.add_peer': self.add_peer,
            'server.banner': self.banner,
            'server.donation_address': self.donation_address,
            'server.features': self.server_features_async,
            'server.peers.subscribe': self.peers_subscribe,
            'server.ping': self.ping,
            'server.version': self.server_version,
'''