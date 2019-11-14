#!/bin/bash
# Huaicheng Li <huaicheng@cs.uchicago.edu>
# Run VM with FEMU support: FEMU as a black-box SSD (FTL managed by the device)

# image directory
IMGDIR=$HOME/imgs/femu/uefi

# virtual machine disk image
OSIMGF=$IMGDIR/boot.qcow2

# virtual NVMe disk image
NVMEIMGF=$IMGDIR/nvme1.raw

# IOS file to install host operating system
OSIOSF=/home/kks/ubuntu-16.04.5-desktop-amd64.iso

# BIOS file to support NVMe normally
BIOSF=$HOME/imgs/OVMF.fd

# virtual NVMe disk size: 16GB
NVMEIMGSZ=16G

# #CPU cores
CPUCORES=6

# Memory size
MEMSIZE=8G

# NIC MAC address to use SSH connection
#  - WARNING: AA:BB:CC:DD:EE:FF is ALREADY used in our lab!
#             You must chagne it to other things like FF:EE:DD:CC:BB:AA
MAC='AA:BB:CC:DD:EE:FF' 


if [[ ! -e "$OSIMGF" ]]; then
	echo ""
	echo "VM disk image couldn't be found ..."
	echo "Please prepare a usable VM image and place it as $OSIMGF"
	echo "Once VM disk image is ready, please rerun this script again"
	echo ""
	exit
fi

# Please match the image file size with the emulated SSD size in vssd1.conf file
rm -rf $NVMEIMGF
./qemu-img create -f raw $NVMEIMGF $NVMEIMGSZ


sudo x86_64-softmmu/qemu-system-x86_64 \
    -name "FEMU-blackbox-SSD" \
    -enable-kvm \
    -cpu host \
    -smp $CPUCORES \
    -m $MEMSIZE \
	-device virtio-scsi-pci,id=scsi0 \
	-device scsi-hd,drive=hd0 \
	-drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
	-netdev tap,id=net0,script=/etc/qemu-ifup-br \
	-device e1000,netdev=net0,mac=$MAC \
	-drive file=$NVMEIMGF,if=none,aio=threads,format=raw,id=id0 \
	-device nvme,femu_mode=1,drive=id0,serial=serial0,id=nvme0 \
	--bios $BIOSF \
	-cdrom $OSIOSF \
    -qmp unix:./qmp-sock,server,nowait 

#
# Please manually run the following commands for better FEMU performance/accuracy
#

echo "VM is up, enjoy it :)"

wait


#### UNUSED PARTS ####

#./pin.sh
#sshsim "~/tsc.sh"
#sshsim "echo 0 | sudo tee /proc/sys/kernel/timer_migration"
#sshsim "echo 0 | sudo tee /sys/kernel/debug/tracing/tracing_on"

# huge page related settings
#echo 25000 | sudo tee /proc/sys/vm/nr_hugepages

#[[ ! -d /dev/hugepages2M ]] && sudo mkdir /dev/hugepages2M && sudo mount -t hugetlbfs none /dev/hugepages2M -o pagesize=2M


# Useful options you may want to further try:
#-object iothread,id=iothread0 \
#-device virtio-blk-pci,iothread=iothread0,drive=id0 \
    #-nographic \
    #-device nvme,drive=id0,serial=serial0,id=nvme0 \
    #-kernel /home/huaicheng/git/linux/arch/x86_64/boot/bzImage \
    #-append "root=/dev/vda1 console=ttyS0,115200n8 console=tty0" \
    #-virtfs local,path=/home/huaicheng/share/,security_model=passthrough,mount_tag=host_share \

    #must come before all other qemu options!!!!!!
    #-trace events=/tmp/events \
    #-object memory-backend-file,id=mem1,size=8G,mem-path=/dev/hugepages2M \
    #-device pc-dimm,id=dimm1,memdev=mem1 \
    #-device virtio-scsi-pci,id=scsi1 \
    #-device scsi-hd,drive=hd1 \
    #-drive file=$IMGDIR/vmdata.qcow2,if=none,aio=native,cache=none,format=qcow2,id=hd1 \

