sudo bpftool prog load ./redirect.bpf.o /sys/fs/bpf/redir_prog
#sudo bpftool prog show pinned /sys/fs/bpf/redir_prog
#mkdir ~/bpffs
#sudo mount -t bpf none ~/bpffs
#sudo bpftool map show name redir_map
#sudo bpftool map pin name redir_map ~/bpffs/redir_map
#./sockmap-update 24533 3 ~/bpffs/redir_map
#bpftool map dump pinned ~/bpffs/redir_map
sudo ./sk-lookup-attach /sys/fs/bpf/redir_prog /sys/fs/bpf/redir_link

sudo bpftool link show pinned /sys/fs/bpf/redir_link
#ls -l /proc/self/ns/net


