#!/bin/bash

echo "[*] clearing dmesg"
dmesg -c

echo "[*] disabling kaslr..."
if grep -qw "nokaslr" /proc/cmdline; then
    echo "[+] KASLR is DISABLED (nokaslr in cmdline)"
else
    echo "[!] KASLR is ENABLED - attempting to disable for next boot..."
    # Add nokaslr to GRUB if not already present
    if ! grep -qw "nokaslr" /etc/default/grub; then
         sed -i 's/^GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"nokaslr /' /etc/default/grub
         update-grub
        echo "[+] 'nokaslr' added to GRUB. You must reboot for KASLR to be disabled."
        echo "[+] Reboot now? (y/N)"
        read answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
             reboot
        else
            echo "[!] KASLR will remain enabled until you reboot."
        fi
    else
        echo "[*] 'nokaslr' already in /etc/default/grub. Just reboot to disable KASLR."
    fi
fi

echo -e "\n\033[1;36m[*] Ensuring environment is ready...\033[0m"
KERN_VER=$(uname -r)

### ===Install basic build tools===
apt update -y >/dev/null
apt install sudo git make gcc gdb tar pip xxd build-essential binutils linux-compiler-gcc-12-x86 linux-kbuild-6.1 wget -y >/dev/null || true
apt install -f -y >/dev/null

#sleep 2
# if [ ! -f "/root/vmlinux" ]; then
#     echo "[*] Downloading latest kvmctf bundle for vmlinux..."
#     wget -q https://storage.googleapis.com/kvmctf/latest.tar.gz
#     tar -xzf latest.tar.gz
#     mv /root/kvmprobes/kvmctf-6.1.74/vmlinux/vmlinux /root
#     echo "[+] vmlinux moved to /root"
# else
#     echo "[+] /root/vmlinux already exists, skipping download."
#fi

sleep 2
echo "[*] downloading necessary headers..."
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb

### ===Install with verification===
sleep 2
echo "[*] Installing necessary headers..."
dpkg -i *.deb || true

sleep 2
echo "[*] getting kvm_prober setup..."
make
make install
make kvm_prober
cp kvm_prober /bin

sleep 2
echo "[*] running exploit..."
chmod +x exploit.sh
./exploit.sh

sleep 2
echo "[*] checking /root/addresses for flag..."
cat /root/addresses

sleep 2
echo "[*] done..."
