# Copyright (c) 2016-2017, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

'''Transaction-related classes and functions.'''

from dataclasses import dataclass
from hashlib import blake2s
from typing import Sequence, Optional

from electrumx.lib.hash import sha256, double_sha256, hash_to_hex_str
from electrumx.lib.script import OpCodes
from electrumx.lib.util import (
    unpack_le_int32_from, unpack_le_int64_from, unpack_le_uint16_from,
    unpack_be_uint16_from,
    unpack_le_uint32_from, unpack_le_uint64_from, pack_le_int32, pack_varint,
    pack_le_uint16, pack_le_uint32, pack_le_int64, pack_varbytes,
    pack_be_uint16,
)

ZERO = bytes(32)
MINUS_1 = 4294967295


@dataclass
class Tx:
    '''Class representing a transaction.'''
    __slots__ = 'version', 'inputs', 'outputs', 'locktime'
    version: int
    inputs: Sequence['TxInput']
    outputs: Sequence['TxOutput']
    locktime: int

    def serialize(self):
        return b''.join((
            pack_le_int32(self.version),
            pack_varint(len(self.inputs)),
            b''.join(tx_in.serialize() for tx_in in self.inputs),
            pack_varint(len(self.outputs)),
            b''.join(tx_out.serialize() for tx_out in self.outputs),
            pack_le_uint32(self.locktime)
        ))


@dataclass
class TxInput:
    '''Class representing a transaction input.'''
    __slots__ = 'prev_hash', 'prev_idx', 'script', 'sequence'
    prev_hash: bytes
    prev_idx: int
    script: bytes
    sequence: int

    def __str__(self):
        script = self.script.hex()
        prev_hash = hash_to_hex_str(self.prev_hash)
        return (f"Input({prev_hash}, {self.prev_idx:d}, script={script}, "
                f"sequence={self.sequence:d})")

    def is_generation(self):
        '''Test if an input is generation/coinbase like'''
        return self.prev_hash == ZERO

    def serialize(self):
        return b''.join((
            self.prev_hash,
            pack_le_uint32(self.prev_idx),
            pack_varbytes(self.script),
            pack_le_uint32(self.sequence),
        ))


@dataclass
class TxOutput:
    __slots__ = 'value', 'pk_script'
    value: int
    pk_script: bytes

    def serialize(self):
        return b''.join((
            pack_le_int64(self.value),
            pack_varbytes(self.pk_script),
        ))

@dataclass
class RangeProofNavio:
    __slots__ = 'Vs', 'Ls', 'Rs', 'A', 'A_wip', 'B', 'r_prime', 's_prime', 'delta_prime', 'alpha_hat', 'tau_x'

    Vs: Sequence[bytes]
    Ls: Sequence[bytes]
    Rs: Sequence[bytes]
    A: bytes
    A_wip: bytes
    B: bytes
    r_prime: bytes
    s_prime: bytes
    delta_prime: bytes
    alpha_hat: bytes
    tau_x: bytes

    def serialize(self):
        # Vs, Ls, Rs are lists of points (bytes), serialize as: varint(count) + concatenated points
        # Note: Ls and Rs are only serialized if Vs.Size() > 0 (matching Navio-core ProofBase::Serialize)
        vs_bytes = b''.join(self.Vs) if self.Vs else b''
        result = [
            pack_varint(len(self.Vs)),
            vs_bytes,
        ]
        if len(self.Vs) > 0:
            ls_bytes = b''.join(self.Ls) if self.Ls else b''
            rs_bytes = b''.join(self.Rs) if self.Rs else b''
            result.extend([
                pack_varint(len(self.Ls)),
                ls_bytes,
                pack_varint(len(self.Rs)),
                rs_bytes,
            ])
        result.extend([
            self.A,
            self.A_wip,
            self.B,
            self.r_prime,
            self.s_prime,
            self.delta_prime,
            self.alpha_hat,
            self.tau_x,
        ])
        return b''.join(result)


@dataclass
class TxBlsctDataNavio:
    __slots__ = 'range_proof','sk', 'ek', 'bk',  'view_tag'
    range_proof: RangeProofNavio
    sk: bytes
    ek: bytes
    bk: bytes
    view_tag: int

    def serialize(self):
        # Note: Order must match Navio-core CTxOutBLSCTData::Serialize() and _read_blsct_data():
        # range_proof, spendingKey (sk), blindingKey (bk), ephemeralKey (ek), view_tag
        # view_tag is uint16_t, which is little-endian in Bitcoin/Navio
        # MclG1Point is serialized as fixed 48 bytes (not varbytes) - see MclG1Point::Serialize()
        return b''.join((
            self.range_proof.serialize(),
            self.sk,  # Fixed 48 bytes, not varbytes
            self.bk,  # Fixed 48 bytes, not varbytes
            self.ek,  # Fixed 48 bytes, not varbytes
            pack_le_uint16(self.view_tag),
        ))

@dataclass
class TxOutputNavio:
    __slots__ = 'value', 'pk_script', 'blsct_data', 'tokenid', 'tokennftid', 'vdata'
    value: int
    pk_script: bytes
    blsct_data: TxBlsctDataNavio
    tokenid: bytes
    tokennftid: int
    vdata: bytes

    def serialize(self):
        flags = 0
        # BLSCT_MARKER: rangeProof.Vs.Size() > 0 OR HasBLSCTKeys()
        # HasBLSCTKeys() = !ephemeralKey.IsZero() || !blindingKey.IsZero() || !spendingKey.IsZero()
        # Keys are bytes (48 bytes for points), check if any are non-zero
        has_blsct_keys = (self.blsct_data.ek and len(self.blsct_data.ek) > 0 and not all(b == 0 for b in self.blsct_data.ek)) or \
                         (self.blsct_data.bk and len(self.blsct_data.bk) > 0 and not all(b == 0 for b in self.blsct_data.bk)) or \
                         (self.blsct_data.sk and len(self.blsct_data.sk) > 0 and not all(b == 0 for b in self.blsct_data.sk))
        if len(self.blsct_data.range_proof.Vs) > 0 or has_blsct_keys:
            flags |= 0x1 << 0
        if self.tokenid and not all(b == 0 for b in self.tokenid):
            flags |= 0x1 << 1
        if self.vdata and len(self.vdata) > 0:
            flags |= 0x1 << 2
        # TRANSPARENT_VALUE_MARKER: value > 0 AND (tokenId.IsNFT() OR predicate.size() > 0)
        # IsNFT() = token != uint256() && subid != std::numeric_limits<uint64_t>::max()
        # predicate.size() > 0 = vdata and len(vdata) > 0
        if self.value > 0 and ((self.tokenid and not all(b == 0 for b in self.tokenid) and self.tokennftid != 0xFFFFFFFFFFFFFFFF) or (self.vdata and len(self.vdata) > 0)):
            flags |= 0x1 << 3

        bytes = []
        if flags == 0:
            bytes.append(pack_le_int64(self.value))
        else:
            bytes.append(pack_le_int64(0x7FFFFFFFFFFFFFFF))  # 64-bit max, not 32-bit
            bytes.append(pack_le_int64(flags))
            if flags & 0x1 << 3:
                bytes.append(pack_le_int64(self.value))
        bytes.append(pack_varbytes(self.pk_script))
        if flags & 0x1 << 0:
            bytes.append(self.blsct_data.serialize())
        if flags & 0x1 << 1:
            bytes.append(self.tokenid)
            bytes.append(pack_le_int64(self.tokennftid))
        if flags & 0x1 << 2:
            bytes.append(pack_varbytes(self.vdata))
        return b''.join(bytes)

    def get_hash(self):
        '''Return the output hash (hash of serialized output), matching Navio-core CTxOut::GetHash().'''
        return double_sha256(self.serialize())


@dataclass
class TXOSpendStatus:
    prev_height: Optional[int]  # block height TXO is mined at. None if the outpoint never existed
    spender_txhash: bytes = None
    spender_height: int = None


class Deserializer:
    '''Deserializes blocks into transactions.

    External entry points are read_tx(), read_tx_and_hash(),
    read_tx_and_vsize() and read_block().

    This code is performance sensitive as it is executed 100s of
    millions of times during sync.
    '''

    TX_HASH_FN = staticmethod(double_sha256)

    def __init__(self, binary, start=0):
        assert isinstance(binary, bytes)
        self.binary = binary
        self.binary_length = len(binary)
        self.cursor = start

    def read_tx(self):
        '''Return a deserialized transaction.'''
        return Tx(
            self._read_le_int32(),  # version
            self._read_inputs(),    # inputs
            self._read_outputs(),   # outputs
            self._read_le_uint32()  # locktime
        )

    def read_tx_and_hash(self):
        '''Return a (deserialized TX, tx_hash) pair.

        The hash needs to be reversed for human display; for efficiency
        we process it in the natural serialized order.
        '''
        start = self.cursor
        return self.read_tx(), self.TX_HASH_FN(self.binary[start:self.cursor])

    def read_tx_and_vsize(self):
        '''Return a (deserialized TX, vsize) pair.'''
        return self.read_tx(), self.binary_length

    def _read_inputs(self):
        read_input = self._read_input
        return [read_input() for i in range(self._read_varint())]

    def _read_input(self):
        prev_hash = self._read_nbytes(32)
        prev_idx = self._read_le_uint32()
        script = self._read_varbytes()
        sequence = self._read_le_uint32()
        return TxInput(
            prev_hash,
            prev_idx,
            script,
            sequence
        )

    def _read_outputs(self):
        read_output = self._read_output
        return [read_output() for i in range(self._read_varint())]

    def _read_output(self):
        return TxOutput(
            self._read_le_int64(),  # value
            self._read_varbytes(),  # pk_script
        )

    def _read_byte(self):
        cursor = self.cursor
        self.cursor += 1
        return self.binary[cursor]

    def _read_nbytes(self, n):
        cursor = self.cursor
        self.cursor = end = cursor + n
        if self.binary_length < end:
            raise ValueError(
                f'Trying to read {n} bytes at position {cursor}, but only '
                f'{self.binary_length - cursor} bytes available (total length: {self.binary_length})'
            )
        return self.binary[cursor:end]

    def _read_varbytes(self):
        return self._read_nbytes(self._read_varint())

    def _read_varint(self):
        if self.cursor >= self.binary_length:
            raise ValueError(
                f'Reading varint at position {self.cursor} but only {self.binary_length} bytes available'
            )
        n = self.binary[self.cursor]
        self.cursor += 1
        if n < 253:
            return n
        if n == 253:
            return self._read_le_uint16()
        if n == 254:
            return self._read_le_uint32()
        if n == 255:
            # Check if we have enough bytes for uint64
            if self.cursor + 8 > self.binary_length:
                raise ValueError(
                    f'Reading uint64 varint at position {self.cursor - 1} but only '
                    f'{self.binary_length - self.cursor + 1} bytes available (need 8)'
                )
            return self._read_le_uint64()
        # Should never reach here, but just in case
        raise ValueError(f'Invalid varint prefix byte: 0x{n:02x} at position {self.cursor - 1}')

    def _read_le_int32(self):
        result, = unpack_le_int32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_int64(self):
        result, = unpack_le_int64_from(self.binary, self.cursor)
        self.cursor += 8
        return result

    def _read_le_uint16(self):
        result, = unpack_le_uint16_from(self.binary, self.cursor)
        self.cursor += 2
        return result

    def _read_be_uint16(self):
        result, = unpack_be_uint16_from(self.binary, self.cursor)
        self.cursor += 2
        return result

    def _read_le_uint32(self):
        result, = unpack_le_uint32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_uint64(self):
        result, = unpack_le_uint64_from(self.binary, self.cursor)
        self.cursor += 8
        return result


@dataclass
class TxNavio:
    '''Class representing transaction that has a time field.'''
    __slots__ = 'version', 'inputs', 'outputs', 'locktime', 'txsig', 'raw'
    version: int
    inputs: Sequence
    outputs: Sequence
    locktime: int
    txsig: bytes
    raw: bytes


@dataclass
class TxNavioSegWit:
    '''Class representing a SegWit transaction with time.'''
    __slots__ = ('version', 'marker', 'flag', 'inputs', 'outputs',
                 'witness', 'locktime', 'txsig', 'raw')
    version: int
    marker: int
    flag: int
    inputs: Sequence
    outputs: Sequence
    witness: Sequence
    locktime: int
    txsig: bytes
    raw: bytes



class DeserializerTxNavio(Deserializer):
    def _read_witness(self, fields):
        read_witness_field = self._read_witness_field
        return [read_witness_field() for _ in range(fields)]

    def _read_witness_field(self):
        read_varbytes = self._read_varbytes
        return [read_varbytes() for _ in range(self._read_varint())]
    
    def _read_input(self):
        '''Navio inputs: prevout.hash (32 bytes), scriptSig (varbytes), nSequence (4 bytes).
        Note: Navio does NOT have prev_idx - it uses hash-only outpoints.'''
        prev_hash = self._read_nbytes(32)  # prevout.hash (output hash, not tx hash)
        script = self._read_varbytes()  # scriptSig
        sequence = self._read_le_uint32()  # nSequence
        return TxInput(
            prev_hash,
            0,  # prev_idx is always 0 for Navio (hash-only outpoints)
            script,
            sequence
        )
    
    def _read_outputs(self):
        read_output = self._read_output
        return [read_output() for i in range(self._read_varint())]

    def _read_blsct_data(self):
        range_proof = self.read_range_proof()
        sk = self.read_point()
        bk = self.read_point()
        ek = self.read_point()
        view_tag = self._read_le_uint16()  # uint16_t is little-endian in Bitcoin/Navio
        return TxBlsctDataNavio(range_proof, sk, ek, bk, view_tag)

    def _read_output(self):
        value = self._read_le_int64()
        blsct_data = TxBlsctDataNavio(RangeProofNavio(b'', b'', b'', b'', b'', b'', b'', b'', b'', b'', b''), b'', b'', b'', 0)
        tokenid = b''
        tokennftid = 0
        vdata = b''
        script = b''
        flags = 0
        if value == 0x7FFFFFFFFFFFFFFF:
            flags = self._read_le_int64()
            if flags & 0x1 << 3:
                value = self._read_le_int64()
        script = self._read_varbytes()
        if flags & 0x1 << 0:
            blsct_data = self._read_blsct_data()
        if flags & 0x1 << 1:
            tokenid = self._read_nbytes(32)
            tokennftid = self._read_le_int64()
        if flags & 0x1 << 2:
            vdata = self._read_varbytes()
        return TxOutputNavio(
            value,  # value
            script,  # pk_script
            blsct_data,
            tokenid,
            tokennftid,
            vdata
        )


    def read_tx_no_segwit(self, start):
        version = self._read_le_int32()
        input_start = self.cursor
        inputs = self._read_inputs()
        input_end = self.cursor
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        txsig = b''
        if version & 1 << 5:
            txsig = self._read_nbytes(96)
        return TxNavio(
            version,
            inputs,
            outputs,
            locktime,
            txsig,
            self.binary[start:self.cursor]
        )

    def _read_tx_parts(self):
        '''Return a (deserialized TX, tx_hash, vsize) tuple.'''
        start = self.cursor
        # Check marker byte (5th byte of transaction, after 4-byte version)
        if self.cursor + 4 >= self.binary_length:
            raise ValueError(
                f'Not enough bytes to read transaction marker at position {self.cursor + 4} '
                f'(only {self.binary_length} bytes available)'
            )
        marker = self.binary[self.cursor + 4]
        if marker:
            tx = self.read_tx_no_segwit(start)
            tx_hash = self.TX_HASH_FN(self.binary[start:self.cursor])
            return tx, tx_hash, self.binary_length

        version = self._read_le_int32()
        orig_ser = self.binary[start:self.cursor]

        marker = self._read_byte()
        flag = self._read_byte()

        start = self.cursor
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        orig_ser += self.binary[start:self.cursor]

        base_size = self.cursor - start
        witness = self._read_witness(len(inputs))

        start = self.cursor
        locktime = self._read_le_uint32()

        txsig = b''
        if version & 1 << 5:
            txsig = self._read_nbytes(96)

        vsize = (3 * base_size + self.binary_length) // 4
        orig_ser += self.binary[start:self.cursor]

        return TxNavioSegWit(
            version, marker, flag, inputs, outputs, witness, locktime, txsig, orig_ser),\
            self.TX_HASH_FN(orig_ser), vsize

    def read_tx(self):
        return self._read_tx_parts()[0]

    def read_tx_and_hash(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, tx_hash

    def read_tx_and_vsize(self):
        tx, tx_hash, vsize = self._read_tx_parts()
        return tx, vsize

    def read_tx_block(self):
        '''Returns a list of (deserialized_tx, tx_hash) pairs.'''
        read = self.read_tx_and_hash
        # Some coins have excess data beyond the end of the transactions
        return [read() for _ in range(self._read_varint())]

    def read_point(self):
        return self._read_nbytes(48)

    def read_scalar(self):
        return self._read_nbytes(32)

    def read_points(self):
        points = []
        for i in range(self._read_varint()):
            points.append(self.read_point())
        return points

    def read_scalars(self):
        scalars = []
        for i in range(self._read_varint()):
            scalars.append(self.read_scalar())
        return scalars

    def read_set_mem_proof(self):
        phi = self.read_point()
        A1 = self.read_point()
        A2 = self.read_point()
        S1 = self.read_point()
        S2 = self.read_point()
        S3 = self.read_point()
        T1 = self.read_point()
        T2 = self.read_point()
        tau_x = self.read_scalar()
        mu = self.read_scalar()
        z_alpha = self.read_scalar()
        z_tau = self.read_scalar()
        z_beta = self.read_scalar()
        t = self.read_scalar()
        Ls = self.read_points()
        Rs = self.read_points()
        a = self.read_scalar()
        b =self.read_scalar()
        omega = self.read_scalar()

    def read_range_proof(self):
        Vs = self.read_points()
        if len(Vs) > 0:
            Ls = self.read_points()
            Rs = self.read_points()
        else:
            Ls = []
            Rs = []
        A = self.read_point()
        A_wip = self.read_point()
        B = self.read_point()
        r_prime = self.read_scalar()
        s_prime = self.read_scalar()
        delta_prime = self.read_scalar()
        alpha_hat = self.read_scalar()
        tau_x = self.read_scalar()

        return RangeProofNavio(Vs, Ls, Rs, A, A_wip, B, r_prime, s_prime, delta_prime, alpha_hat, tau_x)

    def read_range_proof_without_v(self):
        Ls = self.read_points()
        Rs = self.read_points()
        A = self.read_point()
        A_wip = self.read_point()
        B = self.read_point()
        r_prime = self.read_scalar()
        s_prime = self.read_scalar()
        delta_prime = self.read_scalar()
        alpha_hat = self.read_scalar()
        tau_x = self.read_scalar()


    def read_pos_proof(self):
        start = self.cursor
        try:
            self.read_set_mem_proof()
            self.read_range_proof_without_v()
        except (ValueError, IndexError) as e:
            raise ValueError(
                f'Failed to read PoS proof at position {start}: {e}. '
                f'Available bytes: {self.binary_length - start}, total: {self.binary_length}'
            ) from e
        offset = self.cursor - start
        if offset < 0 or self.cursor > self.binary_length:
            raise ValueError(
                f'Invalid PoS proof offset {offset} calculated at position {start}. '
                f'Cursor moved to {self.cursor}, but block length is {self.binary_length}'
            )
        return offset
