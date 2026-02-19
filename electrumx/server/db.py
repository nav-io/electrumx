# Copyright (c) 2016-2020, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Interface to the blockchain database.'''


from array import array
import ast
import os
import time
from bisect import bisect_right
from dataclasses import dataclass
from glob import glob
from typing import Dict, List, Sequence, Tuple, Optional, TYPE_CHECKING, Union

import attr
from aiorpcx import run_in_thread, sleep

import electrumx.lib.util as util
from electrumx.lib.hash import hash_to_hex_str, HASHX_LEN
from electrumx.lib.merkle import Merkle, MerkleCache
from electrumx.lib.util import (
    formatted_time, pack_be_uint16, pack_be_uint32, pack_le_uint64, pack_le_uint32,
    unpack_le_uint32, unpack_be_uint32, unpack_le_uint64
)
from electrumx.lib.tx import TXOSpendStatus
from electrumx.server.storage import db_class, Storage
from electrumx.server.history import (
    History, TXNUM_LEN, TXOUTIDX_LEN, TXOUTIDX_PADDING, pack_txnum, unpack_txnum,
)

if TYPE_CHECKING:
    from electrumx.server.env import Env


@dataclass(order=True)
class UTXO:
    __slots__ = 'tx_num', 'tx_pos', 'tx_hash', 'height', 'value'
    tx_num: int      # index of tx in chain order
    tx_pos: int      # tx output idx
    tx_hash: bytes   # txid
    height: int      # block height
    value: int       # in satoshis


@attr.s(slots=True)
class FlushData:
    height = attr.ib()
    tx_count = attr.ib()
    headers = attr.ib()
    block_tx_hashes = attr.ib()  # type: List[bytes]
    undo_block_tx_hashes = attr.ib()  # type: List[bytes]
    undo_historical_spends = attr.ib()  # type: List[bytes]
    # The following are flushed to the UTXO DB if undo_infos is not None
    undo_infos = attr.ib()  # type: List[Tuple[Sequence[bytes], int]]
    adds = attr.ib()  # type: Dict[bytes, bytes]  # txid+out_idx -> hashX+tx_num+value_sats
    deletes = attr.ib()  # type: List[bytes]  # b'h' db keys, and b'u' db keys
    tip = attr.ib()


class DB:
    '''Simple wrapper of the backend database for querying.

    Performs no DB update, though the DB will be cleaned on opening if
    it was shutdown uncleanly.
    '''

    DB_VERSIONS = (9, )

    utxo_db: Optional['Storage']
    tx_db: Optional['Storage']

    class DBError(Exception):
        '''Raised on general DB errors generally indicating corruption.'''

    def __init__(self, env: 'Env'):
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        self.env = env
        self.coin = env.coin

        # Setup block header size handlers
        if self.coin.STATIC_BLOCK_HEADERS:
            self.header_offset = self.coin.static_header_offset
            self.header_len = self.coin.static_header_len
        else:
            self.header_offset = self.dynamic_header_offset
            self.header_len = self.dynamic_header_len

        self.logger.info(f'switching current directory to {env.db_dir}')
        os.chdir(env.db_dir)

        self.db_class = db_class(self.env.db_engine)
        self.history = History()

        # Key: b'u' + address_hashX + tx_num + output_hash
        # Value: value (8)
        # "at address, at outpoint, there is a UTXO of value v"
        # ---
        # Key: b'h' + output_hash
        # Value: hashX + tx_num
        # "some outpoint created a UTXO at address"
        # ---
        # Key: b'U' + block_height
        # Value: byte-concat list of (hashX + tx_num + value_sats)
        # "undo data: list of UTXOs spent at block height"
        self.utxo_db = None
        self.tx_db = None

        self.fs_height = -1
        self.fs_tx_count = 0
        self.db_height = -1
        self.db_tx_count = 0
        self.db_tip = None  # type: Optional[bytes]
        self.last_flush = time.time()
        self.last_flush_tx_count = 0
        self.wall_time = 0
        self.first_sync = True
        self.db_version = -1

        self.logger.info(f'using {self.env.db_engine} for DB backend')

        # Header merkle cache
        self.merkle = Merkle()
        self.header_mc = MerkleCache(self.merkle, self.fs_block_hashes)

        # on-disk: raw block headers in chain order
        self.headers_file = util.LogicalFile('meta/headers', 2, 16000000)
        # on-disk: cumulative number of txs at the end of height N
        self.tx_counts = None  # type: Optional[array]
        self.tx_counts_file = util.LogicalFile('meta/txcounts', 2, 2000000)
        # on-disk: 32 byte txids in chain order, allows (tx_num -> txid) map
        self.hashes_file = util.LogicalFile('meta/hashes', 4, 16000000)
        if not self.coin.STATIC_BLOCK_HEADERS:
            self.headers_offsets_file = util.LogicalFile(
                'meta/headers_offsets', 2, 16000000)

    async def _read_tx_counts(self):
        if self.tx_counts is not None:
            return
        # tx_counts[N] has the cumulative number of txs at the end of
        # height N.  So tx_counts[0] is 1 - the genesis coinbase
        size = (self.db_height + 1) * 8
        tx_counts = self.tx_counts_file.read(0, size)
        assert len(tx_counts) == size
        self.tx_counts = array('Q', tx_counts)
        if self.tx_counts:
            assert self.db_tx_count == self.tx_counts[-1]
        else:
            assert self.db_tx_count == 0

    async def _open_dbs(self, *, for_sync: bool):
        assert self.utxo_db is None
        assert self.tx_db is None

        self.tx_db = self.db_class('tx', for_sync)

        # First UTXO DB
        self.utxo_db = self.db_class('utxo', for_sync)
        if self.utxo_db.is_new:
            self.logger.info('created new database')
            self.logger.info('creating metadata directory')
            os.mkdir('meta')
            with util.open_file('COIN', create=True) as f:
                f.write(f'ElectrumX databases and metadata for '
                        f'{self.coin.NAME} {self.coin.NET}'.encode())
            if not self.coin.STATIC_BLOCK_HEADERS:
                self.headers_offsets_file.write(0, b'\0\0\0\0\0\0\0\0')
        else:
            self.logger.info(f'opened UTXO DB (for sync: {for_sync})')
        self.read_utxo_state()

        # Then history DB
        self.history.open_db(
            db_class=self.db_class,
            for_sync=for_sync,
            utxo_db_tx_count=self.db_tx_count,
        )
        self.clear_excess_undo_info()

        # Read TX counts (requires meta directory)
        await self._read_tx_counts()

    async def open_for_sync(self):
        '''Open the databases to sync to the daemon.

        When syncing we want to reserve a lot of open files for the
        synchronization.  When serving clients we want the open files for
        serving network connections.
        '''
        await self._open_dbs(for_sync=True)

    async def open_for_serving(self):
        '''Open the databases for serving.  If they are already open they are
        closed first.
        '''
        if self.utxo_db:
            self.logger.info('closing DBs to re-open for serving')
            self.utxo_db.close()
            self.history.close_db()
            self.tx_db.close()
            self.utxo_db = None
            self.tx_db = None
        await self._open_dbs(for_sync=False)

    # Header merkle cache

    async def populate_header_merkle_cache(self):
        self.logger.info('populating header merkle cache...')
        length = max(1, self.db_height - self.env.reorg_limit)
        start = time.monotonic()
        await self.header_mc.initialize(length)
        elapsed = time.monotonic() - start
        self.logger.info(f'header merkle cache populated in {elapsed:.1f}s')

    async def header_branch_and_root(self, length, height):
        return await self.header_mc.branch_and_root(length, height)

    # Flushing
    def assert_flushed(self, flush_data: FlushData):
        '''Asserts state is fully flushed.'''
        assert flush_data.tx_count == self.fs_tx_count == self.db_tx_count
        assert flush_data.height == self.fs_height == self.db_height
        assert flush_data.tip == self.db_tip
        assert not flush_data.headers
        assert not flush_data.block_tx_hashes
        assert not flush_data.undo_block_tx_hashes
        assert not flush_data.undo_historical_spends
        assert not flush_data.adds
        assert not flush_data.deletes
        assert not flush_data.undo_infos
        self.history.assert_flushed()

    def flush_dbs(self, flush_data: FlushData, flush_utxos, estimate_txs_remaining):
        '''Flush out cached state.  History is always flushed; UTXOs are
        flushed if flush_utxos.'''
        if flush_data.height == self.db_height:
            self.assert_flushed(flush_data)
            return

        start_time = time.time()
        prior_flush = self.last_flush
        tx_delta = flush_data.tx_count - self.last_flush_tx_count

        # Flush to file system
        self.flush_fs(flush_data)

        # Then history
        self.flush_history()

        # Flush state last as it reads the wall time.
        with self.utxo_db.write_batch() as batch:
            if flush_utxos:
                self.flush_utxo_db(batch, flush_data)
            self.flush_state(batch)

        # Update and put the wall time again - otherwise we drop the
        # time it took to commit the batch
        self.flush_state(self.utxo_db)

        elapsed = self.last_flush - start_time
        self.logger.info(f'flush took '
                         f'{elapsed:.1f}s.  Height {flush_data.height:,d} '
                         f'txs: {flush_data.tx_count:,d} ({tx_delta:+,d})')

        # Catch-up stats
        if self.utxo_db.for_sync:
            flush_interval = self.last_flush - prior_flush
            tx_per_sec_gen = int(flush_data.tx_count / self.wall_time)
            tx_per_sec_last = 1 + int(tx_delta / flush_interval)
            eta = estimate_txs_remaining() / tx_per_sec_last
            self.logger.info(f'tx/sec since genesis: {tx_per_sec_gen:,d}, '
                             f'since last flush: {tx_per_sec_last:,d}')
            self.logger.info(f'sync time: {formatted_time(self.wall_time)}  '
                             f'ETA: {formatted_time(eta)}')

    def flush_fs(self, flush_data: FlushData):
        '''Write headers, tx counts and block tx hashes to the filesystem.

        The first height to write is self.fs_height + 1.  The FS
        metadata is all append-only, so in a crash we just pick up
        again from the height stored in the DB.
        '''
        prior_tx_count = (self.tx_counts[self.fs_height]
                          if self.fs_height >= 0 else 0)
        assert len(flush_data.block_tx_hashes) == len(flush_data.headers)
        assert flush_data.height == self.fs_height + len(flush_data.headers)
        assert flush_data.tx_count == (self.tx_counts[-1] if self.tx_counts
                                       else 0)
        assert len(self.tx_counts) == flush_data.height + 1
        hashes = b''.join(flush_data.block_tx_hashes)
        assert len(hashes) % 32 == 0
        assert len(hashes) // 32 == flush_data.tx_count - prior_tx_count

        # Write the headers, tx counts, and tx hashes
        start_time = time.monotonic()
        height_start = self.fs_height + 1
        offset = self.header_offset(height_start)
        self.headers_file.write(offset, b''.join(flush_data.headers))
        self.fs_update_header_offsets(offset, height_start, flush_data.headers)
        flush_data.headers.clear()

        offset = height_start * self.tx_counts.itemsize
        self.tx_counts_file.write(offset,
                                  self.tx_counts[height_start:].tobytes())
        offset = prior_tx_count * 32
        self.hashes_file.write(offset, hashes)
        
        # Store tx_hashes per block height in database for fast lookups
        # This avoids reading from the sequential file each time
        # Each element in block_tx_hashes is the concatenated hashes for one block
        for idx, block_hashes in enumerate(flush_data.block_tx_hashes):
            height = height_start + idx
            block_key = b'B' + pack_be_uint32(height)
            self.tx_db.put(block_key, block_hashes)
        
        flush_data.block_tx_hashes.clear()
        self.fs_height = flush_data.height
        self.fs_tx_count = flush_data.tx_count

        if self.utxo_db.for_sync:
            elapsed = time.monotonic() - start_time
            self.logger.info(f'flushed filesystem data in {elapsed:.2f}s')

    def flush_history(self):
        self.history.flush()

    def flush_utxo_db(self, batch, flush_data: FlushData):
        '''Flush the cached DB writes and UTXO set to the batch.'''
        # Care is needed because the writes generated by flushing the
        # UTXO state may have keys in common with our write cache or
        # may be in the DB already.
        start_time = time.monotonic()
        add_count = len(flush_data.adds)
        spend_count = len(flush_data.deletes) // 2

        # Spends
        batch_delete = batch.delete
        for key in sorted(flush_data.deletes):
            batch_delete(key)
        flush_data.deletes.clear()

        # New UTXOs
        batch_put = batch.put
        for key, value in flush_data.adds.items():
            # key: output_hash, value: hashX+tx_num+value_sats
            hashX = value[:HASHX_LEN]
            tx_num = value[HASHX_LEN: HASHX_LEN+TXNUM_LEN]
            value_sats = value[-8:]
            batch_put(b'h' + key, hashX + tx_num)
            batch_put(b'u' + hashX + tx_num + key, value_sats)
        flush_data.adds.clear()

        # New undo information
        self.flush_undo_infos(batch_put, flush_data.undo_infos)
        flush_data.undo_infos.clear()

        if self.utxo_db.for_sync:
            block_count = flush_data.height - self.db_height
            tx_count = flush_data.tx_count - self.db_tx_count
            elapsed = time.monotonic() - start_time
            self.logger.info(f'flushed {block_count:,d} blocks with '
                             f'{tx_count:,d} txs, {add_count:,d} UTXO adds, '
                             f'{spend_count:,d} spends in '
                             f'{elapsed:.1f}s, committing...')

        self.db_height = flush_data.height
        self.db_tx_count = flush_data.tx_count
        self.db_tip = flush_data.tip

    def flush_state(self, batch):
        '''Flush chain state to the batch.'''
        now = time.time()
        self.wall_time += now - self.last_flush
        self.last_flush = now
        self.last_flush_tx_count = self.fs_tx_count
        self.write_utxo_state(batch)

    def flush_backup(self, flush_data: FlushData, touched_hashxs):
        '''Like flush_dbs() but when backing up.  All UTXOs are flushed.'''
        assert not flush_data.headers
        assert not flush_data.block_tx_hashes
        assert flush_data.height < self.db_height
        self.history.assert_flushed()
        assert len(flush_data.undo_block_tx_hashes) == self.db_height - flush_data.height

        start_time = time.time()
        tx_delta = flush_data.tx_count - self.last_flush_tx_count

        tx_hashes = []
        for block in flush_data.undo_block_tx_hashes:
            tx_hashes += [*util.chunks(block, 32)]
        flush_data.undo_block_tx_hashes.clear()
        assert len(tx_hashes) == -tx_delta

        self.backup_fs(flush_data.height, flush_data.tx_count)
        self.history.backup(
            hashXs=touched_hashxs,
            tx_count=flush_data.tx_count,
            tx_hashes=tx_hashes,
            spends=flush_data.undo_historical_spends,
        )
        flush_data.undo_historical_spends.clear()
        
        # Delete tx_keys and block index entries for disconnected blocks
        # Delete block index entries (b'B' + height) for heights being disconnected
        with self.tx_db.write_batch() as batch:
            for tx_hash in tx_hashes:
                # Delete tx_keys (b'k' + tx_hash) for disconnected transactions
                tx_keys_key = b'k' + tx_hash
                batch.delete(tx_keys_key)
            
            # Delete block index entries for all heights being disconnected
            for height in range(flush_data.height + 1, self.db_height + 1):
                block_key = b'B' + pack_be_uint32(height)
                batch.delete(block_key)
        
        with self.utxo_db.write_batch() as batch:
            self.flush_utxo_db(batch, flush_data)
            # Flush state last as it reads the wall time.
            self.flush_state(batch)

        elapsed = self.last_flush - start_time
        self.logger.info(f'backup flush took '
                         f'{elapsed:.1f}s.  Height {flush_data.height:,d} '
                         f'txs: {flush_data.tx_count:,d} ({tx_delta:+,d})')

    def fs_update_header_offsets(self, offset_start, height_start, headers):
        if self.coin.STATIC_BLOCK_HEADERS:
            return
        offset = offset_start
        offsets = []
        for h in headers:
            offset += len(h)
            offsets.append(pack_le_uint64(offset))
        # For each header we get the offset of the next header, hence we
        # start writing from the next height
        pos = (height_start + 1) * 8
        self.headers_offsets_file.write(pos, b''.join(offsets))

    def dynamic_header_offset(self, height):
        assert not self.coin.STATIC_BLOCK_HEADERS
        offset, = unpack_le_uint64(self.headers_offsets_file.read(height * 8, 8))
        return offset

    def dynamic_header_len(self, height):
        return self.dynamic_header_offset(height + 1)\
               - self.dynamic_header_offset(height)

    def backup_fs(self, height, tx_count):
        '''Back up during a reorg.  This just updates our pointers.'''
        self.fs_height = height
        self.fs_tx_count = tx_count
        # Truncate header_mc: header count is 1 more than the height.
        self.header_mc.truncate(height + 1)

    async def raw_header(self, height):
        '''Return the binary header at the given height.'''
        header, n = await self.read_headers(height, 1)
        if n != 1:
            raise IndexError(f'height {height:,d} out of range')
        return header

    async def read_headers(self, start_height, count):
        '''Requires start_height >= 0, count >= 0.  Reads as many headers as
        are available starting at start_height up to count.  This
        would be zero if start_height is beyond self.db_height, for
        example.

        Returns a (binary, n) pair where binary is the concatenated
        binary headers, and n is the count of headers returned.
        '''
        if start_height < 0 or count < 0:
            raise self.DBError(f'{count:,d} headers starting at '
                               f'{start_height:,d} not on disk')

        def read_headers():
            # Read some from disk
            disk_count = max(0, min(count, self.db_height + 1 - start_height))
            if disk_count:
                offset = self.header_offset(start_height)
                size = self.header_offset(start_height + disk_count) - offset
                return self.headers_file.read(offset, size), disk_count
            return b'', 0

        return await run_in_thread(read_headers)

    def fs_tx_hash(self, tx_num: int) -> Tuple[Optional[bytes], int]:
        '''Return a pair (tx_hash, tx_height) for the given tx number.

        If the tx_height is not on disk, returns (None, tx_height).'''
        tx_height = bisect_right(self.tx_counts, tx_num)
        if tx_height > self.db_height:
            tx_hash = None
        else:
            tx_hash = self.hashes_file.read(tx_num * 32, 32)
        return tx_hash, tx_height

    def fs_tx_hashes_at_blockheight(self, block_height):
        '''Return a list of tx_hashes at given block height,
        in the same order as in the block.
        '''
        if block_height > self.db_height:
            raise self.DBError(f'block {block_height:,d} not on disk (>{self.db_height:,d})')
        assert block_height >= 0
        
        # Try to get from database cache first (much faster than reading from sequential file)
        block_key = b'B' + pack_be_uint32(block_height)
        cached_hashes = self.tx_db.get(block_key)
        
        if cached_hashes is not None:
            # Deserialize: concatenated 32-byte hashes
            num_txs = len(cached_hashes) // 32
            return [cached_hashes[idx * 32: (idx+1) * 32] for idx in range(num_txs)]
        
        # Fallback to reading from sequential file (for backwards compatibility)
        if block_height > 0:
            first_tx_num = self.tx_counts[block_height - 1]
        else:
            first_tx_num = 0
        num_txs_in_block = self.tx_counts[block_height] - first_tx_num
        tx_hashes = self.hashes_file.read(first_tx_num * 32, num_txs_in_block * 32)
        assert num_txs_in_block == len(tx_hashes) // 32
        tx_hashes_list = [tx_hashes[idx * 32: (idx+1) * 32] for idx in range(num_txs_in_block)]
        
        # Cache it in the database for future lookups
        self.tx_db.put(block_key, tx_hashes)
        
        return tx_hashes_list

    async def tx_hashes_at_blockheight(self, block_height):
        return await run_in_thread(self.fs_tx_hashes_at_blockheight, block_height)

    async def fs_block_hashes(self, height, count):
        headers_concat, headers_count = await self.read_headers(height, count)
        if headers_count != count:
            raise self.DBError(f'only got {headers_count:,d} headers starting '
                               f'at {height:,d}, not {count:,d}')
        offset = 0
        headers = []
        for n in range(count):
            hlen = self.header_len(height + n)
            headers.append(headers_concat[offset:offset + hlen])
            offset += hlen

        return [self.coin.header_hash(header) for header in headers]

    async def limited_history_triples(
            self,
            *,
            hashX: bytes,
            limit: Optional[int] = 1000,
            txnum_min: Optional[int] = None,
            txnum_max: Optional[int] = None,
    ) -> Sequence[Tuple[bytes, int, int]]:
        '''Return an unpruned, sorted list of (tx_hash, height, tx_num) tuples of
        confirmed transactions that touched the address, earliest in
        the blockchain first.  Includes both spending and receiving
        transactions.  By default returns at most 1000 entries.  Set
        limit to None to get them all.
        txnum_min can be used to seek into the history and start there (>=) (instead of genesis).
        txnum_max can be used to stop early (<).
        '''
        def read_history():
            tx_nums = list(self.history.get_txnums(
                hashX=hashX, limit=limit, txnum_min=txnum_min, txnum_max=txnum_max))
            fs_tx_hash = self.fs_tx_hash
            return [(*fs_tx_hash(tx_num), tx_num) for tx_num in tx_nums]

        while True:
            history = await run_in_thread(read_history)
            if all(tx_hash is not None for tx_hash, height, tx_num in history):
                return history
            self.logger.warning(f'limited_history: tx hash '
                                f'not found (reorg?), retrying...')
            await sleep(0.25)

    async def limited_history(
            self,
            *,
            hashX: bytes,
            limit: Optional[int] = 1000,
            txnum_min: Optional[int] = None,
            txnum_max: Optional[int] = None,
    ) -> Sequence[Tuple[bytes, int]]:
        '''Return a list of (tx_hash, height) tuples of confirmed txs that touched hashX.'''
        triples = await self.limited_history_triples(
            hashX=hashX, limit=limit, txnum_min=txnum_min, txnum_max=txnum_max)
        return [(tx_hash, height) for (tx_hash, height, tx_num) in triples]

    def fs_txnum_for_txhash(self, tx_hash: bytes) -> Optional[int]:
        return self.history.get_txnum_for_txhash(tx_hash)

    async def txnum_for_txhash(self, tx_hash: bytes) -> Optional[int]:
        return await run_in_thread(self.fs_txnum_for_txhash, tx_hash)

    async def get_blockheight_and_txpos_for_txhash(
            self, tx_hash: bytes,
    ) -> Tuple[Optional[int], Optional[int]]:
        '''Returns (block_height, tx_pos) for a confirmed tx_hash.'''
        tx_num = await self.txnum_for_txhash(tx_hash)
        if tx_num is None:
            return None, None
        return self.get_blockheight_and_txpos_for_txnum(tx_num)

    def get_blockheight_and_txpos_for_txnum(
            self, tx_num: int,
    ) -> Tuple[Optional[int], Optional[int]]:
        '''Returns (block_height, tx_pos) for a tx_num.'''
        height = bisect_right(self.tx_counts, tx_num)
        if height > self.db_height:
            return None, None
        assert height > 0
        tx_pos = tx_num - self.tx_counts[height - 1]
        return height, tx_pos

    def get_next_tx_num_after_blockheight(self, height: int) -> Optional[int]:
        '''For given block height, returns the tx_num of the coinbase tx at height+1.
        That is, all txs at height are guaranteed to have tx_num < return value.
        '''
        # tx_counts[N] has the cumulative number of txs at the end of
        # height N.  So tx_counts[0] is 1 - the genesis coinbase
        assert height >= 0, f"height must non-negative, not {height}"
        if len(self.tx_counts) < height:
            return None
        return self.tx_counts[height]

    def fs_spender_for_txo(self, prev_txhash: bytes, txout_idx: int) -> 'TXOSpendStatus':
        '''For an outpoint, returns its spend-status (considering only the DB,
        not the mempool).
        '''
        # prev_txhash is output_hash
        # Check if unspent
        hashX, suffix = self._get_hashX_for_utxo(prev_txhash, 0)
        if hashX:
             # Unspent. suffix is tx_num + output_hash. 
             # We need to extract tx_num from suffix to get height.
             tx_numb = suffix[:TXNUM_LEN]
             tx_num = unpack_txnum(tx_numb)
             
             if self.utxo_db.get(b'u' + hashX + suffix):
                 height, _ = self.get_blockheight_and_txpos_for_txnum(tx_num)
                 return TXOSpendStatus(prev_height=height)
        
        # Spent?
        spender_txnum = self.history.get_spender_txnum_for_txo(prev_txhash)
        if spender_txnum is None:
            return TXOSpendStatus(prev_height=None)
            
        spender_txhash, spender_height = self.fs_tx_hash(spender_txnum)
        return TXOSpendStatus(
            prev_height=-1, # Unknown as we don't store creation height for spent outputs
            spender_txhash=spender_txhash,
            spender_height=spender_height,
        )

    async def spender_for_txo(self, prev_txhash: bytes, txout_idx: int) -> 'TXOSpendStatus':
        return await run_in_thread(self.fs_spender_for_txo, prev_txhash, txout_idx)

    # -- Undo information

    def min_undo_height(self, max_height):
        '''Returns a height from which we should store undo info.'''
        return max_height - self.env.reorg_limit + 1

    def undo_key(self, height: int) -> bytes:
        '''DB key for undo information at the given height.'''
        return b'U' + pack_be_uint32(height)

    def read_undo_info(self, height):
        '''Read undo information from a file for the current height.'''
        return self.utxo_db.get(self.undo_key(height))

    def flush_undo_infos(
            self, batch_put, undo_infos: Sequence[Tuple[Sequence[bytes], int]]
    ):
        '''undo_infos is a list of (undo_info, height) pairs.'''
        for undo_info, height in undo_infos:
            batch_put(self.undo_key(height), b''.join(undo_info))

    def raw_block_prefix(self):
        return 'meta/block'

    def raw_block_path(self, height):
        return f'{self.raw_block_prefix()}{height:d}'

    def read_raw_block(self, height):
        '''Returns a raw block read from disk.  Raises FileNotFoundError
        if the block isn't on-disk.'''
        with util.open_file(self.raw_block_path(height)) as f:
            return f.read(-1)

    def write_raw_block(self, block, height):
        '''Write a raw block to disk.'''
        with util.open_truncate(self.raw_block_path(height)) as f:
            f.write(block)
        # Delete old blocks to prevent them accumulating
        try:
            del_height = self.min_undo_height(height) - 1
            os.remove(self.raw_block_path(del_height))
        except FileNotFoundError:
            pass

    def read_raw_tx(self, hash):
        '''Returns a raw tx read from disk.  Raises FileNotFoundError
        if the block isn't on-disk.'''
        prefix = b't' + hash
        return self.tx_db.get(prefix)

    def write_raw_tx(self, tx, hash):
        '''Write a raw tx to disk.'''
        prefix = b't' + hash
        return self.tx_db.put(prefix, tx)

    def read_tx_keys(self, hash):
        '''Read tx keys from disk'''
        prefix = b'k' + hash
        keys = self.tx_db.get(prefix)
        if keys:
            # Use JSON for faster deserialization (much faster than ast.literal_eval)
            import json
            return json.loads(keys.decode())
        return None

    def write_tx_keys(self, keys, hash):
        '''Write tx keys to disk'''
        prefix = b'k' + hash
        # Use JSON for faster serialization/deserialization
        import json
        return self.tx_db.put(prefix, json.dumps(keys).encode())

    def write_output_hash_to_tx_hash(self, output_hash, tx_hash, serialized_output):
        '''Write output_hash -> serialized_output mapping (Navio-specific: for looking up outputs by hash)
        
        Note: output_hash from get_hash() is in internal format (not reversed).
        But users pass output hashes in display format (reversed), and hex_str_to_hash() reverses them.
        So we need to reverse the hash here to display format to match what users will look up.
        
        Stores the serialized output directly for fast retrieval.
        '''
        # Ensure output_hash is exactly 32 bytes
        if len(output_hash) != 32:
            self.logger.error(f'write_output_hash_to_tx_hash: output_hash length is {len(output_hash)}, expected 32! hash={output_hash.hex()}')
            return
        if serialized_output is None:
            self.logger.error(f'write_output_hash_to_tx_hash: serialized_output is required!')
            return
        # Reverse the hash to display format (what users will pass in)
        # get_hash() returns internal format, but users pass display format
        output_hash_display = output_hash[::-1]  # Reverse bytes to display format
        # Store serialized output directly for fast retrieval
        output_prefix = b'O' + output_hash_display
        self.tx_db.put(output_prefix, serialized_output)
        # Note: LevelDB/RocksDB put() is immediate, no flush needed
    
    def read_serialized_output(self, output_hash):
        '''Read serialized output directly (Navio-specific, optimized for fast retrieval)
        
        Returns the serialized output bytes if found, None otherwise.
        '''
        # Ensure output_hash is exactly 32 bytes
        if len(output_hash) != 32:
            return None
        
        # Reverse the hash to display format (what we stored)
        output_hash_display = output_hash[::-1]  # Reverse bytes to display format
        output_prefix = b'O' + output_hash_display  # 'O' (uppercase) for serialized output
        result = self.tx_db.get(output_prefix)
        
        return result

    async def get_tx_keys(self, hash):
        '''Returns tx keys for a confirmed tx_hash.'''
        return await run_in_thread(self.read_tx_keys, hash)

    async def get_block_txs_keys(self, height):
        '''Returns a list of tx keys for a given block height.'''
        total_start = time.monotonic()
        
        # Get tx hashes
        tx_hashes_start = time.monotonic()
        tx_hashes = await self.tx_hashes_at_blockheight(height)
        tx_hashes_time = time.monotonic() - tx_hashes_start
        
        if tx_hashes:
            # Read all tx_keys in parallel for much better performance
            import asyncio
            
            async def get_tx_keys_async(tx_hash):
                return await run_in_thread(self.read_tx_keys, tx_hash)
            
            # Read all keys in parallel
            read_keys_start = time.monotonic()
            keys_list = await asyncio.gather(*[get_tx_keys_async(tx_hash) for tx_hash in tx_hashes])
            read_keys_time = time.monotonic() - read_keys_start
            
            # Format results
            format_start = time.monotonic()
            result = [(hash_to_hex_str(tx_hash), keys) for tx_hash, keys in zip(tx_hashes, keys_list) if keys is not None]
            format_time = time.monotonic() - format_start
            
            total_time = time.monotonic() - total_start
            self.logger.info(f'[BENCH] get_block_txs_keys(height={height}): '
                           f'tx_hashes={tx_hashes_time*1000:.2f}ms, read_keys={read_keys_time*1000:.2f}ms, '
                           f'format={format_time*1000:.2f}ms, total={total_time*1000:.2f}ms, '
                           f'num_txs={len(tx_hashes)}, num_keys={len(result)}')
            return result
        
        total_time = time.monotonic() - total_start
        self.logger.info(f'[BENCH] get_block_txs_keys(height={height}): total={total_time*1000:.2f}ms, num_txs=0')
        return []

    async def get_range_txs_keys(self, start_height, max_size=10*1024*1024, max_blocks=None):
        '''Returns as many tx keys as possible starting from the given block height.
        Returns (blocks, next_height).
        blocks is a list of blocks, where each block is a list of (tx_hash, keys).
        Stops when response size would exceed max_size, when max_blocks blocks are
        collected (if set), or when the chain tip is reached.
        next_height is where the client should resume fetching (tip + 1 when done).
        '''
        import json

        if start_height > self.db_height:
            return [], start_height

        # Process blocks in batches until we hit size/count limit or reach chain tip
        blocks = []
        current_size = 0
        current_height = start_height
        batch_size = 100  # Process 100 blocks at a time for efficiency

        while current_height <= self.db_height:
            # Enforce max_blocks before fetching more
            if max_blocks is not None and len(blocks) >= max_blocks:
                return blocks[:max_blocks], start_height + max_blocks

            # Calculate how many blocks to fetch in this batch
            remaining_blocks = self.db_height - current_height + 1
            batch_count = min(batch_size, remaining_blocks)
            if max_blocks is not None:
                batch_count = min(batch_count, max_blocks - len(blocks))
            heights = list(range(current_height, current_height + batch_count))

            # Batch 1: fetch tx hashes for all heights in this batch
            def batch_get_tx_hashes(heights_list):
                results = {}
                for height in heights_list:
                    try:
                        results[height] = self.fs_tx_hashes_at_blockheight(height)
                    except Exception:
                        results[height] = None
                return results

            all_tx_hashes = await run_in_thread(batch_get_tx_hashes, heights)

            # Collect all tx hashes to look up keys in a single batch
            all_tx_hashes_flat = []
            for height in heights:
                tx_hashes = all_tx_hashes.get(height)
                if tx_hashes:
                    all_tx_hashes_flat.extend(tx_hashes)

            def batch_get_tx_keys(tx_hashes_list):
                results = {}
                for tx_hash in sorted(tx_hashes_list):
                    results[tx_hash] = self.read_tx_keys(tx_hash)
                return results

            all_tx_keys = await run_in_thread(batch_get_tx_keys, all_tx_hashes_flat)

            # Assemble results for this batch and check size limits
            batch_blocks = []
            batch_size_used = 0

            for height in heights:
                tx_hashes = all_tx_hashes.get(height) or []
                block_keys = []
                for tx_hash in tx_hashes:
                    keys = all_tx_keys.get(tx_hash)
                    if keys is not None:
                        block_keys.append((hash_to_hex_str(tx_hash), keys))

                # Estimate block size more accurately
                # Account for JSON array overhead: each block is in an array with commas
                block_size = len(json.dumps(block_keys, separators=(',', ':')))
                # Add overhead for array structure (commas, brackets) - roughly 2 bytes per block
                block_size += 2

                # If adding this block would exceed max_size, stop here
                # Leave some margin to account for JSON wrapper overhead
                if current_size + block_size > max_size and blocks:
                    # Return what we have so far
                    return blocks, height

                batch_blocks.append(block_keys)
                batch_size_used += block_size

            # Add this batch to results
            blocks.extend(batch_blocks)
            current_size += batch_size_used
            current_height += batch_count

            # Enforce max_blocks after adding batch (in case we exceeded in this batch)
            if max_blocks is not None and len(blocks) >= max_blocks:
                return blocks[:max_blocks], start_height + max_blocks

            # If we've processed all blocks, we're done
            if current_height > self.db_height:
                break

        # Return all blocks we fetched; next_height is tip + 1 when we've returned up to tip
        return blocks, current_height

    def clear_excess_undo_info(self):
        '''Clear excess undo info.  Only most recent N are kept.'''
        prefix = b'U'
        min_height = self.min_undo_height(self.db_height)
        keys = []
        for key, _hist in self.utxo_db.iterator(prefix=prefix):
            height, = unpack_be_uint32(key[-4:])
            if height >= min_height:
                break
            keys.append(key)

        if keys:
            with self.utxo_db.write_batch() as batch:
                for key in keys:
                    batch.delete(key)
            self.logger.info(f'deleted {len(keys):,d} stale undo entries')

        # delete old block files
        prefix = self.raw_block_prefix()
        paths = [path for path in glob(f'{prefix}[0-9]*')
                 if len(path) > len(prefix)
                 and int(path[len(prefix):]) < min_height]
        if paths:
            for path in paths:
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
            self.logger.info(f'deleted {len(paths):,d} stale block files')

    # -- UTXO database

    def read_utxo_state(self):
        state = self.utxo_db.get(b'\0state')
        if not state:
            self.db_height = -1
            self.db_tx_count = 0
            self.db_tip = b'\0' * 32
            self.db_version = max(self.DB_VERSIONS)
            self.wall_time = 0
            self.first_sync = True
        else:
            state = ast.literal_eval(state.decode())
            if not isinstance(state, dict):
                raise self.DBError('failed reading state from DB')
            self.db_version = state['db_version']
            if self.db_version not in self.DB_VERSIONS:
                raise self.DBError(f'your UTXO DB version is {self.db_version} '
                                   f'but this software only handles versions '
                                   f'{self.DB_VERSIONS}')
            # backwards compat
            genesis_hash = state['genesis']
            if isinstance(genesis_hash, bytes):
                genesis_hash = genesis_hash.decode()
            if genesis_hash != self.coin.GENESIS_HASH:
                raise self.DBError(f'DB genesis hash {genesis_hash} does not '
                                   f'match coin {self.coin.GENESIS_HASH}')
            self.db_height = state['height']
            self.db_tx_count = state['tx_count']
            self.db_tip = state['tip']
            self.wall_time = state['wall_time']
            self.first_sync = state['first_sync']

        # These are our state as we move ahead of DB state
        self.fs_height = self.db_height
        self.fs_tx_count = self.db_tx_count
        self.last_flush_tx_count = self.fs_tx_count

        # Upgrade DB
        if self.db_version != max(self.DB_VERSIONS):
            pass  # call future upgrade logic here

        # Log some stats
        self.logger.info(f'UTXO DB version: {self.db_version:d}')
        self.logger.info(f'coin: {self.coin.NAME}')
        self.logger.info(f'network: {self.coin.NET}')
        self.logger.info(f'height: {self.db_height:,d}')
        self.logger.info(f'tip: {hash_to_hex_str(self.db_tip)}')
        self.logger.info(f'tx count: {self.db_tx_count:,d}')
        if self.utxo_db.for_sync:
            self.logger.info(f'flushing DB cache at {self.env.cache_MB:,d} MB')
        if self.first_sync:
            self.logger.info(
                f'sync time so far: {util.formatted_time(self.wall_time)}'
            )

    def write_utxo_state(self, batch):
        '''Write (UTXO) state to the batch.'''
        state = {
            'genesis': self.coin.GENESIS_HASH,
            'height': self.db_height,
            'tx_count': self.db_tx_count,
            'tip': self.db_tip,
            'wall_time': self.wall_time,
            'first_sync': self.first_sync,
            'db_version': self.db_version,
        }
        batch.put(b'\0state', repr(state).encode())

    async def all_utxos(self, hashX):
        '''Return all UTXOs for an address sorted in no particular order.'''
        def read_utxos():
            utxos = []
            utxos_append = utxos.append
            # Key: b'u' + address_hashX + tx_num + output_hash
            # Value: value (8)
            prefix = b'u' + hashX
            for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
                # output_hash is the last 32 bytes
                # tx_num is before that
                
                tx_numb = db_key[len(prefix):len(prefix)+TXNUM_LEN]
                tx_num = unpack_txnum(tx_numb)
                
                value, = unpack_le_uint64(db_value)
                
                tx_hash, height = self.fs_tx_hash(tx_num)
                # tx_pos is not stored, assuming 0 or irrelevant for this coin type
                utxos_append(UTXO(tx_num, 0, tx_hash, height, value))
            return utxos

        while True:
            utxos = await run_in_thread(read_utxos)
            if all(utxo.tx_hash is not None for utxo in utxos):
                return utxos
            self.logger.warning(f'all_utxos: tx hash not '
                                f'found (reorg?), retrying...')
            await sleep(0.25)

    def _get_hashX_for_utxo(
            self, tx_hash: bytes, txout_idx: int,
    ) -> Tuple[Optional[bytes], Optional[bytes]]:
        # tx_hash is output_hash here. txout_idx is ignored.
        
        # Key: b'h' + output_hash
        # Value: hashX + tx_num
        db_key = b'h' + tx_hash
        hdb_val = self.utxo_db.get(db_key)
        if hdb_val is None:
            return None, None
        hashX = hdb_val[:HASHX_LEN]
        tx_numb = hdb_val[HASHX_LEN:]
        return hashX, tx_numb + tx_hash

    async def lookup_utxos(self, prevouts):
        '''For each prevout, lookup it up in the DB and return a (hashX,
        value) pair or None if not found.

        Used by the mempool code.
        '''
        def lookup_hashXs():
            '''Return (hashX, suffix) pairs, or None if not found,
            for each prevout.
            '''
            lookup_hashX = self._get_hashX_for_utxo
            return [lookup_hashX(*prevout) for prevout in prevouts]

        def lookup_utxos(hashX_pairs):
            def lookup_utxo(hashX, suffix):
                if not hashX:
                    # This can happen when the daemon is a block ahead
                    # of us and has mempool txs spending outputs from
                    # that new block
                    return None
                # Key: b'u' + address_hashX + tx_num + output_hash
                # Suffix is tx_num + output_hash
                key = b'u' + hashX + suffix
                db_value = self.utxo_db.get(key)
                if not db_value:
                    # This can happen if the DB was updated between
                    # getting the hashXs and getting the UTXOs
                    return None
                value, = unpack_le_uint64(db_value)
                return hashX, value
            return [lookup_utxo(*hashX_pair) for hashX_pair in hashX_pairs]

        hashX_pairs = await run_in_thread(lookup_hashXs)
        return await run_in_thread(lookup_utxos, hashX_pairs)
