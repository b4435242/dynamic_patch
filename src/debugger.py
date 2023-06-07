import pykd
import psutil

def get_pid_by_name(proc_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == proc_name:
            return proc.info['pid']
    return None

# Define a function to dump the contents of the CPU registers to a file
def dump_registers():
    with open("dump.txt", "a") as f:
        f.write("Registers:\n")
        f.write("EAX: %08x\n" % pykd.reg("eax"))
        f.write("EBX: %08x\n" % pykd.reg("ebx"))
        f.write("ECX: %08x\n" % pykd.reg("ecx"))
        f.write("EDX: %08x\n" % pykd.reg("edx"))
        f.write("ESP: %08x\n" % pykd.reg("esp"))
        f.write("EBP: %08x\n" % pykd.reg("ebp"))
        f.write("ESI: %08x\n" % pykd.reg("esi"))
        f.write("EDI: %08x\n" % pykd.reg("edi"))

# Define a function to dump the contents of the stack to a file
def dump_stack():
    with open("dump.txt", "a") as f:
        f.write("Stack:\n")
        esp = pykd.reg("esp")
        for i in range(16):
            value = pykd.ptr32(esp)
            f.write("%08x: %08x\n" % (esp, value))
            esp += 4

# Define a function to handle the breakpoint event
def on_breakpoint():
    dump_registers()
    dump_stack()
    return False



pid = get_pid_by_name("a.exe")
pykd.attach(pid)

# Set a breakpoint at address 0x00401000
bp_address = 0x00401550
pykd.dbgCommand("bp %08x" % bp_address)

# Start the debugging loop
while True:
    pykd.go()
    if pykd.event().isBreakpoint():
        on_breakpoint()
        pykd.dbgCommand("g")
    elif pykd.event().isExitProcess():
        break

pykd.cleanup()
