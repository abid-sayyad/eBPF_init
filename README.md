# eBPF_init

## Hello.py 
This program that uses the get_syscall_fnname to monitor the system call for "execve".
Whenever the "execve" is called, the attached eBPF programs triggers.
In our case this program prints "Hello World"

## Hello-map.py
This is an extention to the Hello.py. In this program we use BPF Maps.
The eBPF maps stores data at a single place for different BPF programs to access.
In this particular example we read the UserID and process ID whenever "execve" is called.

## Hello-ring-buf.py
This example uses BPF ring buffer which is a improved version of perf buffer. The perf buf has respective buffers attached to CPU cores. Whereas in BPF rung buffer is a common buffer shared between all the CPU cores.
In this example we read the command used, message, PID and User Id for each "execve" call made on the system.

