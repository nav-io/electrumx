import asyncio
import json

from electrumx.server.db import DB


def _make_db(tip, keys_per_block, big_blocks=(), big_size=0):
    db = DB.__new__(DB)
    db.db_height = tip

    def read_tx_keys(tx_hash):
        height = int.from_bytes(tx_hash, 'little')
        size = big_size if height in big_blocks else keys_per_block
        return {'k': 'x' * size}

    db.fs_tx_hashes_at_blockheight = lambda h: [h.to_bytes(32, 'little')]
    db.read_tx_keys = read_tx_keys
    return db


def _run(coro):
    return asyncio.run(coro)


def test_size_limit_mid_batch_does_not_skip_blocks():
    # A large block in the middle of a 100-block batch trips the size limit
    # after earlier blocks of that batch were already assembled; those must
    # be returned, not skipped (next_height points past them).
    db = _make_db(tip=999, keys_per_block=50, big_blocks={150, 420}, big_size=20000)
    max_size = 25000

    start = 0
    seen = []
    while start <= db.db_height:
        blocks, next_height = _run(db.get_range_txs_keys(start, max_size, max_blocks=2000))
        # Contract: blocks cover exactly [start, next_height).
        assert len(blocks) == next_height - start
        seen.extend(range(start, next_height))
        start = next_height
    assert seen == list(range(0, 1000))


def test_returns_contiguous_blocks_matching_next_height():
    db = _make_db(tip=450, keys_per_block=10)
    blocks, next_height = _run(db.get_range_txs_keys(7, 10 * 1024 * 1024, max_blocks=2000))
    assert next_height == 451
    assert len(blocks) == 451 - 7
