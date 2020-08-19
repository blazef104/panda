#!/usr/bin/env python3
# Test of tainted_branch

import os
import time
import keystone
import capstone
import z3

from panda import Panda, ffi
from panda.x86.helper import dump_regs, registers, all_registers
# just load and compare:
# ((((regs['ebx_v'])  - (Extract(32, 0, load(1,0,4,0,((regs['ecx_v'])  + (regs['ds_base_v']))))))) == (0))

# load, mul, compare:
# ((((regs['ebx_v'])  - (Extract(32, 0, LShr((((ZeroExt(64, regs['ebx_v']))  * (ZeroExt(64, regs['eax_v'])))) , (32)))))) == (0))



CODE = b"""
jmp .start

.start:
    # Load data from memory mutate it in EDX a bit - this is the right side of the cmp
    mov edx, [ecx]

    # Multiply INPUT ebx by a const
    imul ebx, 0x2

    # Add INPUT ebx
    add ebx, 1

    cmp ebx, edx    # EBX is mutated input, EDX is related to ABCD
    je .equal

    mov esi, 0x3333
    jmp .end

.equal:
    mov esi, 0x4444
    jmp .end

.end:
nop
"""

# XXX: Both concrete values AND taint labels change during a block. For a given tainted
#      compare, our analysis begins at the start of the basic block when state is
#      loaded from the CPUState into the IR. But when the tainted compare
#      actually happens, we have the mid-block concrete values and taint labels
#      to avoid things getting weird, we cache the values and taint labels for each
#      register at the start of every basic block. This is very slow :(

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
ADDRESS = 0x1000
encoding, count = ks.asm(CODE, ADDRESS)
stop_addr = ADDRESS + len(encoding)

# Create a machine of type 'configurable' but with just a CPU specified (no peripherals or memory maps)
panda = Panda("i386", extra_args=["-M", "configurable", "-nographic"])

panda.load_plugin("taint2")

@panda.cb_after_machine_init
def setup(cpu):
    # After our CPU has been created, allocate memory and set starting state

    # Setup a region of memory
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)
    # Write code into memory
    panda.physical_memory_write(ADDRESS, bytes(encoding))
 
    # Set starting registers
    cpu.env_ptr.eip = ADDRESS

    # "Uncontrolled" (non-tainted) registers
    cpu.env_ptr.regs[registers["ECX"]] = ADDRESS+100
    cpu.env_ptr.regs[registers["EDX"]] = 0x0
    # Set [ecx] to 0x41424344 - Uncontrolled
    panda.physical_memory_write(ADDRESS+100, bytes([0x41, 0x42, 0x43, 0x44]))

    # "Controlled" (tainted) registers: EAX, EBX - note EAX doesn't matter for this example
    cpu.env_ptr.regs[registers["EAX"]] = 0

    # Not equal (False): ESI = 3333
    #cpu.env_ptr.regs[registers["EBX"]] =  0x0

    # equal (True): ESI = 4444 - note EAX doesn't matter
    cpu.env_ptr.regs[registers["EBX"]] =  0x2221a120

    # Taint register(s)
    panda.taint_label_reg(registers["EAX"], 1)
    panda.taint_label_reg(registers["EBX"], 2)

# Before every block disassemble it with capstone
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
@panda.cb_before_block_exec
def before(cpu, tb):
    pc = panda.current_pc(cpu)
    print(f"Before block at 0x{pc:x}")
    code = panda.virtual_memory_read(cpu, pc, tb.size)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

# After the tainted compare block - shutdown
@panda.cb_after_block_exec
def after(cpu, tb, rc):
    pc = panda.current_pc(cpu)
    if pc >= stop_addr-2:
        print("\nSTOP\n")
        dump_regs(panda, cpu)
        print("\n" + "="*30)
        if cpu.env_ptr.regs[registers["ESI"]] == 0x4444:
            print("SATISFIED CONDITION")
        else:
            print("FAILED TO SATISFY CONDITION")
        print("="*30)

        os._exit(0) # TODO: we need a better way to stop here

# CFFI can't typedef structures with unions, like addrs, so this is a hack to fix it
ffi.cdef("""
        typedef struct {
            AddrType typ;
            uint64_t addr_val;
            uint16_t off;
            AddrFlag flag;
        } FakeAddr;
""")

ffi.cdef('typedef void (*on_branch2_t) (FakeAddr, uint64_t);', override=True)
ffi.cdef('void ppp_add_cb_on_branch2(on_branch2_t);')

@panda.ppp("taint2", "on_branch2")
def tainted_branch(addr, size):
    tainted = []
    for offset in range(0, size):
        if panda.taint_check_laddr(addr.addr_val, offset):
            print("TAINTED BRANCH")

            # At the time of the branch we need to determine CONCRETE values for non-tainted
            # registers. As such, let's generate vars for each of them:

            tq = panda.taint_get_laddr(addr.addr_val, offset)
            taint_labels = tq.get_labels()
            print(taint_labels)
            print("\n")

ffi.cdef('typedef void (*on_branch2_constraints_t) (char*);')
ffi.cdef('void ppp_add_cb_on_branch2_constraints(on_branch2_constraints_t);')

# Register values at the start of the last BB
reg_cache = {}

@panda.cb_before_block_exec
def cache(cpu, tb):
    '''
    Cache register values at the start of each BB. Ugh
    WIP: for now, just normal registers
    '''
    global reg_cache

    for name, (qemu_idx, typ, size) in all_registers.items():
        name = name.lower()
        if typ == 0:
            # Normal registers
            if panda.taint_check_reg(qemu_idx):
                reg_cache[name+"_v"] = None
            else:
                val = cpu.env_ptr.regs[qemu_idx]
                reg_cache[name+"_v"] = val

@panda.ppp("taint2", "on_branch2_constraints")
def taint_cmp(s):
    if s == ffi.NULL:
        print("ERR")
        return
    cpu = panda.get_cpu()
    data = ffi.string(s)

    # For each register we need to create a base value
    # tainted values should be bitvecs. non-tainted values should be
    # constants

    regs = {}
    tainted_regs = []
    # For each register, create concrete (BitVecVal) or symbolic (BitVec)
    # depending on taint
    for name, (qemu_idx, typ, size) in all_registers.items():
        name = name.lower()
        if typ == 0:
            # Normal registers - Grab value from reg_cache
            if reg_cache[name+"_v"]: # Concrete val from cache
                val = reg_cache[name+"_v"]
                regs[name+"_v"] = z3.BitVecVal(val, size)
            else:
                # Was tainted at start of block - leave unconstrained
                regs[name+"_v"] = z3.BitVec(name, size)
                tainted_regs.append(name+"_v")

            '''
            if panda.taint_check_reg(qemu_idx):
                print("Register", name, qemu_idx, "is tainted!")
                regs[name+"_v"] = z3.BitVec(name, size)
                tainted_regs.append(name+"_v")

            else:
                val = cpu.env_ptr.regs[qemu_idx]
                regs[name+"_v"] = z3.BitVecVal(val, size)
            '''
        elif typ == 1:
            pass
        elif typ == 2:
            # Segment registers
            # Assign bitvecs
            regs[name+"_base_v"]  = z3.BitVecVal(cpu.env_ptr.segs[qemu_idx].base,  size)
            regs[name+"_flags_v"] = z3.BitVecVal(cpu.env_ptr.segs[qemu_idx].flags, size)
            regs[name+"_limit_v"] = z3.BitVecVal(cpu.env_ptr.segs[qemu_idx].flags, size)

    def Extract(size, start, val):
        end = start+size-1
        return z3.Extract(end, start, val)

    # Unsigned <
    def ULT(a, b):
        return z3.ULT(a, b)

    # Unsigned >
    def UGT(a, b):
        return z3.UGT(a, b)

    # Logical shift right
    def LShr(a, b):
        return z3.LShR(a, b)

    def ZeroExt(a, b):
        return z3.ZeroExt(a, b)

    def URem(a, b):
        return z3.URem(a, b)

    def load(endian, is_store, num_bytes, signed, addr):
        assert(not is_store), "NYI"

        # assumes it's not tainted
        addr_z3_int = z3.BV2Int(addr)
        if addr_z3_int.is_int(): # Concretize and read real data
            addr_conc = int(z3.simplify(addr_z3_int).as_long())
            #print(f"Read concrete data from 0x{addr_conc:x}:")
            conc_data = panda.virtual_memory_read(cpu, addr_conc, num_bytes, fmt='int')
            if endian == 2: # Flip if big-endian
                conc_data = int.from_bytes(conc_data.to_bytes(num_bytes, byteorder='little'), byteorder='big', signed=signed)
            return z3.BitVecVal(conc_data, num_bytes*8)
        else:
            print("WARNING: Variable mem read - assuming unconstrained")
            # Variable address - assume it can return anything
            return z3.BitVec(f'load_{addr}', num_bytes*8)

    def model_to_dict(model):
        # Given a model, return a dict of strings_name: int_val
        # This is fairly terrible, there's certainly a better way
        model_str = str(model)[1:-1] # trim []'s
        r = {}
        for entry in model_str.split(", "):
            name, val = entry.split(" = ")
            name = name.strip()
            val = int(val)
            r[name] = val
        return r

    # XXX: this uses evals!!!

    print(f"\nTainted comparison at: 0x{panda.current_pc(cpu):x} {data.decode()}")
    print("\tSimplified condition:", eval(f"z3.simplify({data.decode()})"))

    s_true = z3.Solver()
    eval(f"s_true.add({data.decode()})")

    if s_true.check() == z3.sat:
        print("Solution found for TRUE branch:")
        m = s_true.model()
        for (reg, val) in sorted(model_to_dict(m).items()):
            print(f"\t {reg} = 0x{val:x}")
    else:
        print("TRUE branch UNSAT")

    s_false = z3.Solver()
    eval(f"s_false.add(z3.Not({data.decode()}))")
    if s_false.check() == z3.sat:
        print("Solution found for FALSE branch:")
        m = s_false.model()
        for (reg, val) in sorted(model_to_dict(m).items()):
            print(f"\t {reg} = 0x{val:x}")
    else:
        print("FALSE branch UNSAT")


panda.enable_precise_pc()

# Start PANDA running. Callback functions will be called as necessary
panda.run()