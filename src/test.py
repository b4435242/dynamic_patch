import angr, argparse, IPython
import load_state

def check_mem_corruption(simgr):
    print(simgr.active)
    if len(simgr.unconstrained):
        for path in simgr.unconstrained:
            if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCCCCCC"]):
                path.add_constraints(path.regs.pc == b"CCCCCCCC")
                if path.satisfiable():
                    simgr.stashes['mem_corrupt'].append(path)
                simgr.stashes['unconstrained'].remove(path)
                simgr.drop(stash='active')
    return simgr

def main():

    p = angr.Project("../test/toy/a.exe", main_opts={'base_addr': 0x7ff62ce61000})
    state = p.factory.blank_state(addr=0x7ff62ce61450)
    
    simgr = p.factory.simgr(state, save_unconstrained=True)
    simgr.stashes['mem_corrupt']  = []
    #load_state.set_regs(state, 'registers')
    #load_state.set_stack(state, 'stack')
    #print(state.mem[state.regs.rsp].uint64_t)
    #print(state.mem[state.regs.rsp+8].uint64_t)

    print(state.regs.rsp)
    print(state.regs.rip)
    simgr.explore(step_func=check_mem_corruption, find=0x7ff62ce614a9)

    #IPython.embed()
    print(simgr.stashes['mem_corrupt'])
    
if __name__ == "__main__":
    main()
