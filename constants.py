# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
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
import json


def read_json(filename, default):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except:
        r = default
    return r


class BitcoinMainnet:

    TESTNET = False
    WIF_PREFIX = 204
    ADDRTYPE_P2PKH = 76
    ADDRTYPE_P2SH = 26
    GENESIS = "00000d6f81d96969bfa1f195a1e349a6129c720c50a255c50ca38163d8286579"
    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    DEFAULT_SERVERS = read_json('servers.json', {})
    CHECKPOINTS = read_json('checkpoints.json', [])

    XPRV_HEADERS = {
        'standard':    0x0488ade4,  # xprv
    }
    XPUB_HEADERS = {
        'standard':    0x0488b21e,  # xpub
    }
    DRKV_HEADER = 0x02fe52f8  # drkv
    DRKP_HEADER = 0x02fe52cc  # drkp
    BIP44_COIN_TYPE = 5


class BitcoinTestnet:

    TESTNET = True
    WIF_PREFIX = 239
    ADDRTYPE_P2PKH = 140
    ADDRTYPE_P2SH = 19
    GENESIS = "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS = read_json('servers_testnet.json', {})
    CHECKPOINTS = read_json('checkpoints_testnet.json', [])

    XPRV_HEADERS = {
        'standard':    0x04358394,  # tprv
    }
    XPUB_HEADERS = {
        'standard':    0x043587cf,  # tpub
    }
    DRKV_HEADER = 0x3a8061a0  # DRKV
    DRKP_HEADER = 0x3a805837  # DRKP
    BIP44_COIN_TYPE = 1


class BitcoinRegtest(BitcoinTestnet):

    GENESIS = "000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e"
    DEFAULT_SERVERS = read_json('servers_regtest.json', {})
    CHECKPOINTS = []


# don't import net directly, import the module instead (so that net is singleton)
net = BitcoinMainnet


def set_mainnet():
    global net
    net = BitcoinMainnet


def set_testnet():
    global net
    net = BitcoinTestnet


def set_regtest():
    global net
    net = BitcoinRegtest
