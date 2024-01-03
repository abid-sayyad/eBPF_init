from bcc import BPF
from time import sleep

program = r"""
    BPF_HASH(counter_table);
    
    int hello(void *ctx){
        u64 uid;
        u64 counter = 0;
        u64 *p;

        uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        p= counter_table.lookup(&uid);
        if(p != 0){
            counter = *p;
        }
        counter++;
        counter_table.update(&uid, &counter);
        return 0;
    }"""
b = BPF(text=program)
syscall_execve = b.get_syscall_fnname("execve")
syscall_openat = b.get_syscall_fnname("openat")
syscall_write = b.get_syscall_fnname("write")
b.attach_kprobe(event=syscall_execve, fn_name="hello")
b.attach_kprobe(event=syscall_openat, fn_name="hello")
b.attach_kprobe(event=syscall_write, fn_name="hello")

#print("The function name of %s in kernel is %s" % ("execve", b.get_syscall_fnname("execve")))
#print("The function name of %s in kernel is %s" % ("openat", b.get_syscall_fnname("openat")))
#print("The function name of %s in kernel is %s" % ("write", b.get_syscall_fnname("write")))


while True:
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
