import copy
from collections import defaultdict
from ethereum import vm
from ethereum import opcodes
from ethereum import transactions
from ethereum import utils
from ethereum import pruning_trie as trie
from ethereum.blocks import Block, BlockHeader, get_block_header
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
from rlp.utils import decode_hex, encode_hex, ascii_chr
import rlp
from tqdm import tqdm

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
        success = True
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
                for bc in b_children:
                    success = success and verify(bc, bc.get_parent())
        super(Chain, self)._update_head(block, forward_pending_transactions)
        # revert the db after chain.head is updated
        if success and reverted_blocks and self.revert_block_cb:
            self.revert_block_cb(reverted_blocks)

def new_block(block, use_parent=True):
    """Create a new block based on a parent block.

    The block will not include any transactions and will not be finalized.
    """
    parent = block.get_parent()
    header = BlockHeader(prevhash=parent.hash,
                            uncles_hash=utils.sha3(rlp.encode([])),
                            coinbase=block.coinbase,
                            state_root=parent.state_root if use_parent else block.state_root,
                            tx_list_root=trie.BLANK_ROOT,
                            receipts_root=trie.BLANK_ROOT,
                            bloom=0,
                            difficulty=block.difficulty,
                            mixhash='',
                            number=parent.number + 1,
                            gas_limit=block.gas_limit,
                            gas_used=0,
                            timestamp=block.timestamp,
                            extra_data=block.extra_data,
                            nonce=b'')
    block = Block(header, [], [], env=parent.env if use_parent else block.env,
                    parent=parent, making=True)
    block.ancestor_hashes = [parent.hash] + parent.ancestor_hashes
    block.log_listeners = parent.log_listeners
    return block

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
        self.progress_bar = True

        # sanitize the configured addrs
        for addr in self.start_blocks.keys():
            new_addr = addr
            if new_addr[0:2] == '0x':
                new_addr = new_addr[2:]

            if new_addr != addr:
                self.start_blocks[new_addr] = self.start_blocks[addr]
                del self.start_blocks[addr]

    def sync(self, start_block):
        if self.start_block is not None:
            start_block = self.start_block

        # reprocess blocks up to head after casting from CachedBlock to Block
        if start_block is not None and start_block >= 0:
            block_range = range(start_block, self.chain.head.number)
            if self.progress_bar:
                block_range = tqdm(block_range)
            for block_num in block_range:
                block_hash = self.chain.index.get_block_by_number(block_num)
                block = self.chain.get(block_hash)
                self.process_block(block)

    # callback parameter order: method, address, self, *[arguments]
    def _callback(self, method, addr, *args):
        print '_callback', method, addr, args

    def process_block(self, block):
        tmp_block = new_block(block)
        for tx in block.get_transactions():
            apply_transaction(tmp_block, tx, self._callback)
        self.on_block(tmp_block)

    # called with each processed block
    def on_block(self, block):
        print 'on_block', block
        pass

    def on_revert_blocks(self, blocks):
        print 'on_revert_blocks', blocks
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

        # list of msgs, logs, creates in chrono order, used so cbs are called in correct order
        self.activities = []

        # mapping from block.snapshot and msg + relevant info
        self.msgs_by_id = {}
        self.logs_by_id = defaultdict(list)
        self.creates_by_id = defaultdict(list)
        self.current_msg = None
        self.msg_confirms_remaining = {}
        self.successes = set()

    def initialize_msg(self, msg_id, msg):
        self.msgs_by_id[msg_id] = (msg.to, msg_id, msg)
        self.msg_confirms_remaining[msg_id] = msg.depth
        self.activities.append((msg_id, 'msg'))
        self.current_msg = msg_id

    def update_msg_status(self, msg_id, msg, result):
        delset = set()
        for m in self.msg_confirms_remaining:
            confirms = self.msg_confirms_remaining[m]
            if confirms == msg.depth:
                self.msg_confirms_remaining[m] -= result
            if confirms > msg.depth:
                delset.add(m)
            if self.msg_confirms_remaining[m] < 0:
                self.successes.add(m)

        for m in delset:
            del self.msg_confirms_remaining[m]

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
        for msg_id, method in self.activities:
            data = getattr(self, method + 's_by_id')[msg_id]

            if type(data) is list:
                data = data.pop()

            if msg_id in self.successes:
                self.cb(method, *data)

    def _create(self, msg):
        address = msg.sender

        result, gas_remained, new_address = create_contract(self, msg)

        if result:
            self.activities.append((self.current_msg, 'create'))
            self.creates_by_id[self.current_msg].append((address, new_address))

        return result, gas_remained, new_address

    def _msg(self, msg):
        msg_copy = copy.copy(msg)
        msg_id = self.snap_hash(msg_copy, self._block)
        prev_msg = self.current_msg
        self.initialize_msg(msg_id, msg_copy)
        result, gas_remained, data = _apply_msg(self, msg, self.get_code(msg.code_address))
        gas_used = self.gas_left - gas_remained
        self.current_msg = prev_msg
        self.gas_left = gas_remained
        self.msgs_by_id[msg_id] += (result, gas_used, data)
        self.update_msg_status(msg_id, msg, result)

        if msg.depth == 0:
            self.callbacks()

        return result, gas_remained, data

    def _log(self, addr, topics, data):
        self.logs_by_id[self.current_msg].append((addr, topics, data))
        self.activities.append((self.current_msg, 'log'))
        self._block.add_log(Log(addr, topics, data))


def apply_transaction(block, tx, cb=None, validate=True):
    eth_call = False
    def dummy_cb(*args, **kwargs):
        pass

    if cb is None:
        cb = dummy_cb
        eth_call = True

    if validate:
        validate_transaction(block, tx)

    log_tx.debug('TX NEW', tx_dict=tx.log_dict())
    # start transacting #################
    block.increment_nonce(tx.sender)

    intrinsic_gas = intrinsic_gas_used(tx)
    if block.number >= block.config['HOMESTEAD_FORK_BLKNUM']:
        assert tx.s * 2 < transactions.secpk1n
        if not tx.to or tx.to == CREATE_CONTRACT_ADDRESS:
            intrinsic_gas += opcodes.CREATE[3]
            if tx.startgas < intrinsic_gas:
                raise InsufficientStartGas(rp('startgas', tx.startgas, intrinsic_gas))

    # buy startgas
    if validate:
        assert block.get_balance(tx.sender) >= tx.startgas * tx.gasprice

    block.delta_balance(tx.sender, -tx.startgas * tx.gasprice)
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
        assert utils.is_numeric(gas_remained)
        log_tx.debug('_create_', result=result, gas_remained=gas_remained, data=data)

    assert gas_remained >= 0

    log_tx.debug("TX APPLIED", result=result, gas_remained=gas_remained,
                 data=data)

    if not result:  # 0 = OOG failure in both cases
        log_tx.debug('TX FAILED', reason='out of gas',
                     startgas=tx.startgas, gas_remained=gas_remained)
        block.gas_used += tx.startgas
        block.delta_balance(block.coinbase, tx.gasprice * tx.startgas)
        output = b''
        success = 0
    else:
        log_tx.debug('TX SUCCESS', data=data)
        gas_used = tx.startgas - gas_remained
        block.refunds += len(set(block.suicides)) * opcodes.GSUICIDEREFUND
        if block.refunds > 0:
            log_tx.debug('Refunding', gas_refunded=min(block.refunds, gas_used // 2))
            gas_remained += min(block.refunds, gas_used // 2)
            gas_used -= min(block.refunds, gas_used // 2)
            block.refunds = 0
        # sell remaining gas
        block.delta_balance(tx.sender, tx.gasprice * gas_remained)
        block.delta_balance(block.coinbase, tx.gasprice * gas_used)
        block.gas_used += gas_used
        if tx.to:
            output = b''.join(map(ascii_chr, data))
        else:
            output = data
        success = 1
    block.commit_state()
    suicides = block.suicides
    block.suicides = []
    for s in suicides:
        block.ether_delta -= block.get_balance(s)
        block.set_balance(s, 0)
        block.del_account(s)
    block.add_transaction_to_list(tx)
    block.logs = []
    return success, output
