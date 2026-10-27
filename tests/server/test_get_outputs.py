import asyncio
import types

import pytest
from aiorpcx import RPCError

from electrumx.lib.hash import hex_str_to_hash
from electrumx.server.session import ElectrumX


def _session(stored, max_send=1_000_000):
    s = types.SimpleNamespace()
    s.GET_OUTPUTS_MAX_COUNT = ElectrumX.GET_OUTPUTS_MAX_COUNT
    s.GET_OUTPUTS_BW_COST_SHARE = ElectrumX.GET_OUTPUTS_BW_COST_SHARE
    s.env = types.SimpleNamespace(max_send=max_send)
    s.db = types.SimpleNamespace(read_serialized_output=lambda h: stored.get(h))
    s.bw_cost_per_byte = 1 / 5000
    s.cost = 1000.0

    def bump_cost(delta):
        s.cost = max(0, s.cost + delta)
    s.bump_cost = bump_cost
    return s


def _call(s, hashes):
    return asyncio.run(ElectrumX.transaction_get_outputs(s, hashes))


def _h(i):
    return f'{i:064x}'


def test_aligned_with_missing_as_none():
    stored = {hex_str_to_hash(_h(1)): b'\x01\x02', hex_str_to_hash(_h(3)): b'\xff'}
    s = _session(stored)
    assert _call(s, [_h(1), _h(2), _h(3)]) == ['0102', None, 'ff']


def test_truncated_to_max_send():
    stored = {hex_str_to_hash(_h(i)): bytes(1000) for i in range(100)}
    s = _session(stored, max_send=20_000)
    res = _call(s, [_h(i) for i in range(100)])
    # every returned item is complete and in request order; the rest is
    # left for a follow-up request
    assert 0 < len(res) < 100
    assert all(r == '00' * 1000 for r in res)
    assert len(res) * 2003 + 2 <= 20_000 * 0.8


def test_refunds_most_of_the_bandwidth_cost():
    stored = {hex_str_to_hash(_h(i)): bytes(1000) for i in range(100)}
    s = _session(stored)
    _call(s, [_h(i) for i in range(100)])
    sent = 100 * 2003 * s.bw_cost_per_byte  # what aiorpcx bills on send
    charged = s.cost + sent - 1000.0
    assert charged == pytest.approx(0.1 + 0.01 * 100 + sent * 0.1, rel=0.01)


def test_rejects_bad_input():
    s = _session({})
    with pytest.raises(RPCError):
        _call(s, 'notalist')
    with pytest.raises(RPCError):
        _call(s, ['zz'])
    with pytest.raises(RPCError):
        _call(s, [_h(i) for i in range(ElectrumX.GET_OUTPUTS_MAX_COUNT + 1)])
