from ethereum import vm
from ethereum import opcodes
from ethereum import transactions
from ethereum.blocks import Block
from ethereum.chain import Chain as EthChain
from ethereum.config import Env, default_config
from ethereum.exceptions import *
from ethereum.processblock import (
    _apply_msg,
    create_contract,
    CREATE_CONTRACT_ADDRESS,
    intrinsic_gas_used,
    log_tx,
    validate_transaction,
    verify,
    VMExt
)
from ethereum.slogging import get_logger
from pyethapp.eth_service import ChainService as EthChainService
log_chain = get_logger('eth.chain')

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

class ChainService(EthChain):
    current_block = 0
    addrs = set()
    start_blocks = {}

    ## Config: {<address>: <startBlock>} or [<address>]
    ## startBlock === 0     => start from genesis
    ## startBlock < -1      => start from HEAD - <startBlock> + 1
    ## startBlock === None  => start from HEAD
    def __init__(self, app, config={}):
        super(ChainService, self).__init__(app)
        sce = self.config['eth']
        env = Env(self.db, sce['block'])
        coinbase = app.services.accounts.coinbase
        self.chain = Chain(env, new_head_cb=self._on_new_head, coinbase=coinbase, process_block_cb=self.process_block, revert_block_cb=self.on_revert_blocks)
        # Load past blocks and parse for particular txs
        pass

    def _callback(self, ext, method, addr, args):
        if not addr in self.addrs or not hasattr(self, 'on_' + method):
            return
        getattr(self, 'on_' + method)(ext, addr, args)

    def process_block(self, block):
        for tx in block.transaction_list:
            apply_transaction(block, tx, self._callback)
        self.on_block(block)

    # called with each processed block
    def on_block(self, block):
        pass

    def on_revert_blocks(self, blocks):
        pass

    # call sent to address
    def on_msg(self, ext, addr, args):
        pass

    def on_log(self, ext, addr, args):
        pass

# Override VMExt injecting callbacks before each log and inter-contract msg
class CapVMExt(VMExt):
    def __init__(self, block, tx, cb):
        # super(CapVMExt, self).__init__(block, tx)
        VMExt.__init__(self, block, tx)
        self.log = self._log
        self.msg = self._msg
        self.cb = cb

    def _msg(self, msg):
        self.cb(self, 'msg', msg.to, [msg, self.get_code(msg.code_address)])
        return _apply_msg(self, msg, self.get_code(msg.code_address))

    def _log(self, addr, topics, data):
        self.cb(self, 'log', addr, [msg, topics, data])
        self._block.add_log(Log(addr, topics, data))

# forked from pyethereum.processblock, except uses CapVMExt
def apply_transaction(block, tx, cb):
    # validate_transaction(block, tx)

    log_tx.debug('TX NEW', tx_dict=tx.log_dict())

    # start transacting #################

    # block.increment_nonce(tx.sender)

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
    # p.delta_balance(tx.sender, -tx.startgas * tx.gasprice)
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

    '''
    if not result:  # 0 = OOG failure in both cases
        log_tx.debug('TX FAILED', reason='out of gas',
                     startgas=tx.startgas, gas_remained=gas_remained)
        # block.gas_used += tx.startgas
        # block.delta_balance(block.coinbase, tx.gasprice * tx.startgas)
        output = b''
        success = 0
    else:
        log_tx.debug('TX SUCCESS', data=data)
        gas_used = tx.startgas - gas_remained
        # block.refunds += len(set(block.suicides)) * opcodes.GSUICIDEREFUND
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

    # block.commit_state()
    # suicides = block.suicides

    block.suicides = []
    for s in suicides:
        block.ether_delta -= block.get_balance(s)
        block.set_balance(s, 0)
        block.del_account(s)
    block.add_transaction_to_list(tx)
    block.logs = []
    return success, output
    '''
    return
