# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling asynchronous connections to a blockchain
daemon.'''

import asyncio
import itertools
import time
from calendar import timegm
from struct import pack
from typing import TYPE_CHECKING, Type

import aiohttp
from aiorpcx import JSONRPC

from electrumx.lib.hash import hash_to_hex_str, hex_str_to_hash
from electrumx.lib.util import (class_logger, hex_to_bytes, json_deserialize,
                                json_serialize, pack_varint,
                                unpack_le_uint16_from)

if TYPE_CHECKING:
    from electrumx.lib.coins import Coin


class DaemonError(Exception):
    '''Raised when the daemon returns an error in its results.'''


class WarmingUpError(Exception):
    '''Internal - when the daemon is warming up.'''


class ServiceRefusedError(Exception):
    '''Internal - when the daemon doesn't provide a JSON response, only an HTTP error, for
    some reason.'''


class Daemon:
    '''Handles connections to a daemon at the given URL.'''

    WARMING_UP = -28
    id_counter = itertools.count()

    def __init__(
            self,
            coin: Type['Coin'],
            url,
            *,
            max_workqueue=10,
            init_retry=0.25,
            max_retry=4.0,
    ):
        self.coin = coin
        self.logger = class_logger(__name__, self.__class__.__name__)
        self.url_index = None
        self.urls = []
        self.set_url(url)
        # Limit concurrent RPC calls to this number.
        # See DEFAULT_HTTP_WORKQUEUE in bitcoind, which is typically 16
        self.workqueue_semaphore = asyncio.Semaphore(value=max_workqueue)
        self.init_retry = init_retry
        self.max_retry = max_retry
        self._height = None
        self.available_rpcs = {}
        self.session = None

        self._networkinfo_cache = (None, 0)
        self._networkinfo_lock = asyncio.Lock()

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(connector=self.connector())
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.session.close()
        self.session = None

    def connector(self):
        return None

    def set_url(self, url):
        '''Set the URLS to the given list, and switch to the first one.'''
        urls = url.split(',')
        urls = [self.coin.sanitize_url(url) for url in urls]
        for n, url in enumerate(urls):
            status = '' if n else ' (current)'
            logged_url = self.logged_url(url)
            self.logger.info(f'daemon #{n + 1} at {logged_url}{status}')
        self.url_index = 0
        self.urls = urls

    def current_url(self):
        '''Returns the current daemon URL.'''
        return self.urls[self.url_index]

    def logged_url(self, url=None):
        '''The host and port part, for logging.'''
        url = url or self.current_url()
        return url[url.rindex('@') + 1:]

    def failover(self):
        '''Call to fail-over to the next daemon URL.

        Returns False if there is only one, otherwise True.
        '''
        if len(self.urls) > 1:
            self.url_index = (self.url_index + 1) % len(self.urls)
            self.logger.info(f'failing over to {self.logged_url()}')
            return True
        return False

    async def _send_data(self, data):
        async with self.workqueue_semaphore:
            async with self.session.post(self.current_url(), data=data) as resp:
                kind = resp.headers.get('Content-Type', None)
                if kind == 'application/json':
                    return await resp.json(loads=json_deserialize)
                text = await resp.text()
                text = text.strip() or resp.reason
                raise ServiceRefusedError(text)

    async def _send(self, payload, processor):
        '''Send a payload to be converted to JSON.

        Handles temporary connection issues.  Daemon reponse errors
        are raise through DaemonError.
        '''
        def log_error(error):
            nonlocal last_error_log, retry
            now = time.monotonic()
            if now - last_error_log > 60:
                last_error_log = now
                self.logger.error(f'{error}.  Retrying occasionally...')
            if retry == self.max_retry and self.failover():
                retry = 0

        on_good_message = None
        last_error_log = 0
        data = json_serialize(payload)
        retry = self.init_retry
        while True:
            try:
                result = await self._send_data(data)
                result = processor(result)
                if on_good_message:
                    self.logger.info(on_good_message)
                return result
            except asyncio.TimeoutError:
                log_error('timeout error')
            except aiohttp.ServerDisconnectedError:
                log_error('disconnected')
                on_good_message = 'connection restored'
            except ConnectionResetError:
                log_error('connection reset')
                on_good_message = 'connection restored'
            except aiohttp.ClientConnectionError:
                log_error('connection problem - check your daemon is running')
                on_good_message = 'connection restored'
            except aiohttp.ClientError as e:
                log_error(f'daemon error: {e}')
                on_good_message = 'running normally'
            except ServiceRefusedError as e:
                log_error(f'daemon service refused: {e}')
                on_good_message = 'running normally'
            except WarmingUpError:
                log_error('starting up checking blocks')
                on_good_message = 'running normally'

            await asyncio.sleep(retry)
            retry = max(min(self.max_retry, retry * 2), self.init_retry)

    async def _send_single(self, method, params=None):
        '''Send a single request to the daemon.'''
        def processor(result):
            err = result['error']
            if not err:
                return result['result']
            if err.get('code') == self.WARMING_UP:
                raise WarmingUpError
            raise DaemonError(err)

        payload = {'method': method, 'id': next(self.id_counter)}
        if params:
            payload['params'] = params
        return await self._send(payload, processor)

    async def _send_vector(self, method, params_iterable, replace_errs=False):
        '''Send several requests of the same method.

        The result will be an array of the same length as params_iterable.
        If replace_errs is true, any item with an error is returned as None,
        otherwise an exception is raised.'''
        def processor(result):
            errs = [item['error'] for item in result if item['error']]
            if any(err.get('code') == self.WARMING_UP for err in errs):
                raise WarmingUpError
            if not errs or replace_errs:
                return [item['result'] for item in result]
            raise DaemonError(errs)

        payload = [{'method': method, 'params': p, 'id': next(self.id_counter)}
                   for p in params_iterable]
        if payload:
            return await self._send(payload, processor)
        return []

    async def _is_rpc_available(self, method):
        '''Return whether given RPC method is available in the daemon.

        Results are cached and the daemon will generally not be queried with
        the same method more than once.'''
        available = self.available_rpcs.get(method)
        if available is None:
            available = True
            try:
                await self._send_single(method)
            except DaemonError as e:
                err = e.args[0]
                error_code = err.get("code")
                available = error_code != JSONRPC.METHOD_NOT_FOUND
            self.available_rpcs[method] = available
        return available

    async def block_hex_hashes(self, first, count):
        '''Return the hex hashes of count block starting at height first.'''
        params_iterable = ((h, ) for h in range(first, first + count))
        return await self._send_vector('getblockhash', params_iterable)

    async def deserialised_block(self, hex_hash):
        '''Return the deserialised block with the given hex hash.'''
        return await self._send_single('getblock', (hex_hash, True))

    async def raw_blocks(self, hex_hashes):
        '''Return the raw binary blocks with the given hex hashes.'''
        params_iterable = ((h, False) for h in hex_hashes)
        blocks = await self._send_vector('getblock', params_iterable)
        # Convert hex string to bytes
        return [hex_to_bytes(block) for block in blocks]

    async def mempool_hashes(self):
        '''Update our record of the daemon's mempool hashes.'''
        return await self._send_single('getrawmempool')

    async def estimatefee(self, block_count, estimate_mode=None):
        '''Return the fee estimate for the block count.  Units are whole
        currency units per KB, e.g. 0.00000995, or -1 if no estimate
        is available.
        '''
        if estimate_mode:
            args = (block_count, estimate_mode)
        else:
            args = (block_count, )
        if await self._is_rpc_available('estimatesmartfee'):
            estimate = await self._send_single('estimatesmartfee', args)
            return estimate.get('feerate', -1)
        return await self._send_single('estimatefee', args)

    async def getnetworkinfo(self):
        '''Return the result of the 'getnetworkinfo' RPC call.'''
        async with self._networkinfo_lock:
            cache_val, cache_time = self._networkinfo_cache
            if time.time() - cache_time < 60:  # seconds
                return cache_val
            val = await self._send_single('getnetworkinfo')
            self._networkinfo_cache = (val, time.time())
            return val

    async def relayfee(self):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        network_info = await self.getnetworkinfo()
        return network_info['relayfee']

    async def getrawtransaction(self, hex_hash, verbose=False, blockhash=None):
        '''Return the serialized raw transaction with the given hash.'''
        # Cast to int because some coin daemons are old and require it
        verbose = int(verbose)

        if blockhash is None:
            return await self._send_single('getrawtransaction', (hex_hash, verbose))
        else:
            # given a blockhash, modern bitcoind can lookup the tx even without txindex:
            # https://github.com/bitcoin/bitcoin/pull/10275
            return await self._send_single('getrawtransaction', (hex_hash, verbose, blockhash))
          
    async def gettransactionkeys(self, hex_hash):
        '''Return the transaction keys with the given hash.'''
        return await self._send_single('gettransactionkeys', (hex_hash, ))

    async def resolvename(self, name, resolvesub):
        '''Resolves a dotNav name.'''
        return await self._send_single('resolvename', (name, resolvesub, ))

    async def gettoken(self, id):
        '''Returns info from a token.'''
        return await self._send_single('gettoken', (id, ))

    async def getnft(self, id, subid, get_utxo=False):
        '''Returns info from a token.'''
        return await self._send_single('getnft', (id, subid, get_utxo, ))

    async def listproposals(self, filter):
        return await self._send_single('listproposals',
                                       (filter, ))

    async def listconsultations(self, filter):
        return await self._send_single('listconsultations',
                                       (filter, ))

    async def getcfunddbstatehash(self):
        return await self._send_single('getcfunddbstatehash')

    async def getconsensusparameters(self, expanded):
        return await self._send_single('getconsensusparameters', (expanded, ))

    async def viewaggregationsession(self, expanded):
        return await self._send_single('viewaggregationsession', (expanded, ))

    async def getstakervote(self, script):
        return await self._send_single('getstakervote', (script, ))

    async def getrawtransactions(self, hex_hashes, replace_errs=True):
        '''Return the serialized raw transactions with the given hashes.

        Replaces errors with None by default.'''
        params_iterable = ((hex_hash, 0) for hex_hash in hex_hashes)
        txs = await self._send_vector('getrawtransaction', params_iterable,
                                      replace_errs=replace_errs)
        # Convert hex strings to bytes
        return [hex_to_bytes(tx) if tx else None for tx in txs]

    async def broadcast_transaction(self, raw_tx):
        '''Broadcast a transaction to the network.'''
        return await self._send_single('sendrawtransaction', (raw_tx, ))

    async def height(self):
        '''Query the daemon for its current height.'''
        self._height = await self._send_single('getblockcount')
        return self._height

    def cached_height(self):
        '''Return the cached daemon height.

        If the daemon has not been queried yet this returns None.'''
        return self._height


class DashDaemon(Daemon):

    async def masternode_broadcast(self, params):
        '''Broadcast a transaction to the network.'''
        return await self._send_single('masternodebroadcast', params)

    async def masternode_list(self, params):
        '''Return the masternode status.'''
        return await self._send_single('masternodelist', params)

    async def protx(self, params):
        '''Set of commands to execute ProTx related actions.'''
        return await self._send_single('protx', params)


class FakeEstimateFeeDaemon(Daemon):
    '''Daemon that simulates estimatefee and relayfee RPC calls. Coin that
    wants to use this daemon must define ESTIMATE_FEE & RELAY_FEE'''

    async def estimatefee(self, block_count):
        '''Return the fee estimate for the given parameters.'''
        return self.coin.ESTIMATE_FEE

    async def relayfee(self):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        return self.coin.RELAY_FEE


class LegacyRPCDaemon(Daemon):
    '''Handles connections to a daemon at the given URL.

    This class is useful for daemons that don't have the new 'getblock'
    RPC call that returns the block in hex, the workaround is to manually
    recreate the block bytes. The recreated block bytes may not be the exact
    as in the underlying blockchain but it is good enough for our indexing
    purposes.'''

    async def raw_blocks(self, hex_hashes):
        '''Return the raw binary blocks with the given hex hashes.'''
        params_iterable = ((h, ) for h in hex_hashes)
        block_info = await self._send_vector('getblock', params_iterable)

        blocks = []
        for i in block_info:
            raw_block = await self.make_raw_block(i)
            blocks.append(raw_block)

        # Convert hex string to bytes
        return blocks

    async def make_raw_header(self, b):
        pbh = b.get('previousblockhash')
        if pbh is None:
            pbh = '0' * 64
        return b''.join([
            pack('<L', b.get('version')),
            hex_str_to_hash(pbh),
            hex_str_to_hash(b.get('merkleroot')),
            pack('<L', self.timestamp_safe(b['time'])),
            pack('<L', int(b.get('bits'), 16)),
            pack('<L', int(b.get('nonce')))
        ])

    async def make_raw_block(self, b):
        '''Construct a raw block'''

        header = await self.make_raw_header(b)

        transactions = []
        if b.get('height') > 0:
            transactions = await self.getrawtransactions(b.get('tx'), False)

        raw_block = header
        num_txs = len(transactions)
        if num_txs > 0:
            raw_block += pack_varint(num_txs)
            raw_block += b''.join(transactions)
        else:
            raw_block += b'\x00'

        return raw_block

    def timestamp_safe(self, t):
        if isinstance(t, int):
            return t
        return timegm(time.strptime(t, "%Y-%m-%d %H:%M:%S %Z"))


class FakeEstimateLegacyRPCDaemon(LegacyRPCDaemon, FakeEstimateFeeDaemon):
    pass


class PreLegacyRPCDaemon(LegacyRPCDaemon):
    '''Handles connections to a daemon at the given URL.

    This class is useful for daemons that don't have the new 'getblock'
    RPC call that returns the block in hex, and need the False parameter
    for the getblock'''

    async def deserialised_block(self, hex_hash):
        '''Return the deserialised block with the given hex hash.'''
        return await self._send_single('getblock', (hex_hash, False))


class SmartCashDaemon(Daemon):

    async def masternode_broadcast(self, params):
        '''Broadcast a smartnode to the network.'''
        return await self._send_single('smartnodebroadcast', params)

    async def masternode_list(self, params):
        '''Return the smartnode status.'''
        return await self._send_single('smartnodelist', params)

    async def smartrewards(self, params):
        '''Return smartrewards data.'''
        return await self._send_single('smartrewards', params)


class ZcoinMtpDaemon(Daemon):

    def strip_mtp_data(self, raw_block):
        if self.coin.is_mtp(raw_block):
            return \
                raw_block[:self.coin.MTP_HEADER_DATA_START*2] + \
                raw_block[self.coin.MTP_HEADER_DATA_END*2:]
        return raw_block

    async def raw_blocks(self, hex_hashes):
        '''Return the raw binary blocks with the given hex hashes.'''
        params_iterable = ((h, False) for h in hex_hashes)
        blocks = await self._send_vector('getblock', params_iterable)
        # Convert hex string to bytes
        return [hex_to_bytes(self.strip_mtp_data(block)) for block in blocks]

    async def masternode_broadcast(self, params):
        '''Broadcast a transaction to the network.'''
        return await self._send_single('znodebroadcast', params)

    async def masternode_list(self, params):
        '''Return the masternode status.'''
        return await self._send_single('znodelist', params)

    async def protx(self, params):
        '''Set of commands to execute ProTx related actions.'''
        return await self._send_single('protx', params)
