import asyncio
import json
import types

import pytest
from aiorpcx import RPCSession

from electrumx.server.session import ElectrumX

HEADER_LEN = 80
BW_COST_PER_BYTE = 1 / 5000


@pytest.fixture(autouse=True)
def billing_send(monkeypatch):
    # what aiorpcx's _send_message does to the cost, without a transport
    async def _send_message(self, message):
        self.bump_cost(len(message) * self.bw_cost_per_byte)
    monkeypatch.setattr(RPCSession, '_send_message', _send_message)


def _session(chain_len=100_000, cost=0.0):
    s = object.__new__(ElectrumX)
    s.bw_cost_per_byte = BW_COST_PER_BYTE
    s._bw_discount_bytes = 0.0

    async def read_headers(start, count):
        n = max(0, min(count, chain_len - start))
        return bytes(HEADER_LEN * n), n
    s.db = types.SimpleNamespace(read_headers=read_headers)
    s.cost = cost

    def bump_cost(delta):
        s.cost = max(0, s.cost + delta)
    s.bump_cost = bump_cost
    return s


def _call(s, start, count):
    async def go():
        res = await ElectrumX.block_headers(s, start, count)
        await s._send_message(json.dumps({'result': res}).encode())
        return res
    return asyncio.run(go())


def test_returns_capped_chunk():
    s = _session()
    res = _call(s, 0, 5000)
    assert res['count'] == ElectrumX.MAX_CHUNK_SIZE
    assert res['max'] == ElectrumX.MAX_CHUNK_SIZE
    assert len(res['hex']) == 2 * HEADER_LEN * ElectrumX.MAX_CHUNK_SIZE


@pytest.mark.parametrize('start_cost', [0.0, 900.0])
def test_full_chunk_is_cheap_even_on_a_fresh_session(start_cost):
    s = _session(cost=start_cost)
    _call(s, 0, 2016)
    hex_bw = 2 * HEADER_LEN * 2016 * BW_COST_PER_BYTE
    charged = s.cost - start_cost
    # count share + 10% of the hex bandwidth + full price for the JSON wrapper
    assert charged == pytest.approx(2016 / 500 + hex_bw * 0.1, abs=0.1)
    assert s._bw_discount_bytes == 0


def test_fresh_sync_stays_under_soft_limit():
    # the whole Navio mainnet chain, as a fresh wallet fetches it
    s = _session(chain_len=84_336)
    for start in range(0, 84_336, 2016):
        _call(s, start, 2016)
    assert s.cost < 1000   # default COST_SOFT_LIMIT


def test_past_tip_returns_nothing():
    s = _session(chain_len=10)
    res = _call(s, 50, 2016)
    assert res['count'] == 0 and res['hex'] == ''
