from bcc import BPF

program = r"""
    BPF_PERF_OUTPUT(output);

    struct data_t {
        int pid;
        int uid;
        char command[16];
        char message[12];
        char message2[12];
    };

    int hello(void *ctx) {
        struct data_t data = {};
        char message[11] = "Hello Abid";
        char message2[11] = "Hello Baby";
    
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
        bpf_get_current_comm(&data.command, sizeof(data.command));
        
        if((data.pid)%2 == 0)
            bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
            
        else
            bpf_probe_read_kernel(&data.message, sizeof(data.message), message2);

            
        //uncomment while using user space Odd/ Even classification
        //bpf_probe_read_kernel(&data.message2, sizeof(data.message2), message2);

        output.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
"""
b = BPF(text = program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

def print_event(cpu, data, size):
    data = b["output"].event(data)

    print(f"{data.pid} {data.uid} {data.command.decode()}" + \
            f" { data.message.decode()}")


    #User space program for printing different messages for odd and even PIDs
    #if((data.pid)%2 == 0):
    #    print(f"{data.pid} {data.uid} {data.command.decode()}" + \
    #            f" { data.message.decode()}")
    #else:
    #     print(f"{data.pid} {data.uid} {data.command.decode()}" + \
    #            f" { data.message2.decode()}")

b["output"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
