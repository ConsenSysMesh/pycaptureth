import copy
from ethereum import vm
from ethereum import opcodes
from ethereum import transactions
from ethereum import utils
from ethereum.blocks import Block
from ethereum.chain import Chain as EthChain
from ethereum.config import Env, default_config
from ethereum.exceptions import *
from ethereum.processblock import (
    _apply_msg,
    create_contract,
    CREATE_CONTRACT_ADDRESS,
    intrinsic_gas_used,
    Log,
    log_tx,
    validate_transaction,
    verify,
    VMExt
)
from ethereum.utils import safe_ord
from ethereum.slogging import get_logger
from pyethapp.eth_service import ChainService as EthChainService
from rlp.utils import decode_hex, encode_hex

log_chain = get_logger('eth.chain')

def tuplify(alist):
    if alist is None:
        return ()
    if not isinstance(alist, list):
        return alist
    return tuple(map(tuplify, alist))

class Chain(EthChain):
    def __init__(self, env, genesis=None, new_head_cb=None, coinbase='\x00' * 20, process_block_cb=None, revert_block_cb=None):
        super(Chain, self).__init__(env, genesis, new_head_cb, coinbase)
        self.revert_block_cb=revert_block_cb
        self.process_block_cb=process_block_cb

    def add_block(self, block, forward_pending_transactions=True):
        success = super(Chain, self).add_block(block, forward_pending_transactions)
        # new block successfuly added
        if success and self.process_block_cb:
            self.process_block_cb(block)
        return success

    def _update_head(self, block, forward_pending_transactions=True):
        reverted_blocks = []
        if block.number > 0:
            b = block.get_parent()
            h = self.head
            b_children = []
            if b.hash != h.hash:
                log_chain.warn('reverting')
                # revert head back to number of block.parent
                while h.number > b.number:
                    reverted_blocks.append(h)
                    h = h.get_parent()
                # if b's parent is ahead of head
                while b.number > h.number:
                    b_children.append(b)
                    b = b.get_parent()
                # b & h now have same number, wind back one at a time until
                # hashes match
                while b.hash != h.hash:
                    reverted_blocks.append(h)
                    h = h.get_parent()
                    b_children.append(b)
                    b = b.get_parent()
                success = True
                for bc in b_children:
                    success = success and verify(bc, bc.get_parent())
                if success and self.revert_block_cb:
                    self.revert_block_cb(reverted_blocks)
        super(Chain, self)._update_head(block, forward_pending_transactions)

class ChainService(EthChainService):
    start_blocks = {}
    start_block = None

    ## Config: {<address>: <startBlock>} or [<address>]
    ## startBlock === 0     => start from genesis
    ## startBlock < -1      => start from HEAD - <startBlock> + 1
    ## startBlock === None  => start from HEAD
    def __init__(self, app):
        super(ChainService, self).__init__(app)
        sce = self.config['eth']
        env = Env(self.db, sce['block'])
        coinbase = app.services.accounts.coinbase
        self.chain = Chain(env, new_head_cb=self._on_new_head, coinbase=coinbase, process_block_cb=self.process_block, revert_block_cb=self.on_revert_blocks)

        # sanitize the configured addrs
        for addr in self.start_blocks.keys():
            new_addr = addr
            if new_addr[0:2] == '0x':
                new_addr = new_addr[2:]

            if new_addr != addr:
                self.start_blocks[new_addr] = self.start_blocks[addr]
                del self.start_blocks[addr]


        start_block = None
        # start at the minimum block number requested
        block_candidates = [v for v in self.start_blocks.values() if isinstance(v, int) and v >= 0]
        if block_candidates:
            start_block = min(block_candidates)
        if self.start_block is not None:
            start_block = self.start_block

        # reprocess blocks up to head after casting from CachedBlock to Block
        if start_block is not None and start_block >= 0:
            for block_num in range(start_block, self.chain.head.number):
                block_hash = self.chain.index.get_block_by_number(block_num)
                block = self.chain.get(block_hash)
                block.__class__ = Block
                self.process_block(block)

    # callback parameter order: method, address, self, *[arguments]
    def _callback(self, method, addr, ctx, *args):
        # unsupported callback
        if not hasattr(self, 'on_' + method):
            return

        def cb():
            getattr(self, 'on_' + method)(utils.encode_hex(addr), ctx, *args)

        if self.start_block is None and not len(self.start_blocks.keys()):
            cb()

        hex_addr = utils.encode_hex(addr)
        # addr not configured
        if self.start_block is None and hex_addr not in self.start_blocks:
            return

        if self.start_block is None:
            start_block_num = self.start_blocks[hex_addr]
        else:
            start_block_num = self.start_block

        cur_block = ctx._block

        # addr doesn't care about the current block
        if start_block_num > cur_block.number:
            return

        # wait for HEAD
        if start_block_num < 0 and cur_block != self.chain.head:
            return

        # wait for start_block_num
        if start_block_num >= 0 and cur_block.number < start_block_num:
            return

        cb()

    def process_block(self, block):
        for tx in block.transaction_list:
            apply_transaction(block, tx, self._callback)
        self.on_block(block)

    # called with each processed block
    def on_block(self, block):
        print 'on_block', block
        pass

    def on_revert_blocks(self, blocks):
        print 'on_revert_blocks', blocks
        pass

    # call sent to address
    def on_msg(self, addr, *args):
        print 'on_msg', addr, args
        pass

    def on_log(self, addr, *args):
        print 'on_log', addr, args
        pass

# Override VMExt injecting callbacks before each log and inter-contract msg
class CapVMExt(VMExt):

    def __init__(self, block, tx, cb):
        VMExt.__init__(self, block, tx)
        self._tx = tx
        self.gas_left = tx.startgas
        self.log = self._log
        self.msg = self._msg
        self.create = self._create
        self.cb = cb

        # list of msgs in chrono order, used so msgs are cb-ed in correct order
        self.msgs = []
        self.logs = []
        # mapping from block.snapshot and msg + relevant info
        self.msgs_by_snap_hash = {}

    def initialize_msg(self, msg_id, msg):
        self.msgs_by_snap_hash[msg_id] = [msg]
        self.msgs.append(msg_id)

    # TODO: double check, but collisions here should not be possible since
    # calls necessarily will use gas or fail
    @staticmethod
    def snap_hash(msg, block):
        def custom_snapshot(block):
            return {
                'state': block.state.root_hash,
                'gas': block.gas_used,
                'txs': block.transactions.root_hash,
                'suicides': block.suicides,
                'logs': block.logs,
                'journal': block.journal,
                'ether_delta': block.ether_delta
            }

        snap = custom_snapshot(block)
        # add the msg.depth to the hash to accounbt for the case where a CALL
        # results in no gas or state change
        snap['depth'] = msg.depth
        for key in ['logs', 'journal', 'suicides']:
            snap[key] = tuplify(snap[key])
        return hash(frozenset(snap.items()))


    def callbacks(self):
        for msg_id in self.msgs:
            msg = self.msgs_by_snap_hash[msg_id][0]
            self.cb(*['msg', msg.to, msg_id, self] + self.msgs_by_snap_hash[msg_id])

        for addr, topics, data in self.logs:
            self.cb('log', addr, self, topics, data)

    def _create(self, msg):
        output = create_contract(self, msg)
        self.callbacks()
        return output

    def _msg(self, msg):
        msg_copy = copy.copy(msg)
        msg_id = self.snap_hash(msg_copy, self._block)
        self.initialize_msg(msg_id, msg_copy)
        result, gas_remained, data = _apply_msg(self, msg, self.get_code(msg.code_address))
        gas_used = self.gas_left - gas_remained
        self.gas_left = gas_remained
        self.msgs_by_snap_hash[msg_id] += [result, gas_used, data]

        if msg.depth == 0 and result == 1:
            self.callbacks()

        return result, gas_remained, data

    def _log(self, addr, topics, data):
        self.logs.append((addr, topics, data))
        self._block.add_log(Log(addr, topics, data))

# forked from pyethereum.processblock, except uses CapVMExt
def apply_transaction(block, tx, cb):
    log_tx.debug('TX NEW', tx_dict=tx.log_dict())

    # start transacting #################
    p = block.get_parent()

    intrinsic_gas = intrinsic_gas_used(tx)
    if block.number >= block.config['HOMESTEAD_FORK_BLKNUM']:
        assert tx.s * 2 < transactions.secpk1n
        if not tx.to or tx.to == CREATE_CONTRACT_ADDRESS:
            intrinsic_gas += opcodes.CREATE[3]
            if tx.startgas < intrinsic_gas:
                raise InsufficientStartGas(rp('startgas', tx.startgas, intrinsic_gas))

    # buy startgas
    assert p.get_balance(tx.sender) >= tx.startgas * tx.gasprice
    message_gas = tx.startgas - intrinsic_gas
    message_data = vm.CallData([safe_ord(x) for x in tx.data], 0, len(tx.data))
    message = vm.Message(tx.sender, tx.to, tx.value, message_gas, message_data, code_address=tx.to)

    # MESSAGE
    ext = CapVMExt(block, tx, cb)
    if tx.to and tx.to != CREATE_CONTRACT_ADDRESS:
        result, gas_remained, data = ext._msg(message)
        log_tx.debug('_res_', result=result, gas_remained=gas_remained, data=data)
    else:  # CREATE
        result, gas_remained, data = create_contract(ext, message)
        ext.callbacks()
        assert utils.is_numeric(gas_remained)
        log_tx.debug('_create_', result=result, gas_remained=gas_remained, data=data)

    assert gas_remained >= 0

    log_tx.debug("TX APPLIED", result=result, gas_remained=gas_remained,
                 data=data)
    return
