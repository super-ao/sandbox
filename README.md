## Sandbox

Small sandbox where I had fun with libraries

### ebpf / bpf

For this specific project, you need to extract you own `vmlinux.h` from your kernel, use the following command: 
```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```
