# EyeON VM Deployment Guide

This guide assumes you already have one of these artifacts:

- `eyeon-debian12-amd64.qcow2`
- `eyeon-debian12-arm64.qcow2`

## Choose the Right Image

- Use `amd64` for Intel/AMD hosts.
- Use `arm64` for Apple Silicon and other arm64 hosts.

The appliance is a bootable disk image. You do not need a separate ISO or kernel/initrd.

Default login:

- `eyeon / eyeon`
- `debian / debian`

The VM is headless and defaults to DHCP networking through
`systemd-networkd`. This is intentional: it is not the default Debian/cloud-init
networking mechanism. After login, read `/home/eyeon/QUICKSTART.txt` for local
network diagnostics, the disabled static-network example, and the optional NFS
workflow.

Recommended starting size:

- 2 vCPU
- 4 GB RAM
- imported qcow2 as the primary boot disk

## Nutanix AHV

1. Upload the qcow2 to Nutanix Image Service.
2. Create a new VM.
3. Attach the uploaded image as the boot disk.
4. Give the VM at least 2 vCPU and 4 GB RAM.
5. Attach it to a network with DHCP.
6. Boot the VM and log in as `eyeon`.

## Linux (libvirt / virsh)

Example:

```bash
virt-install \
  --name eyeon-debian12-amd64 \
  --memory 4096 \
  --vcpus 2 \
  --import \
  --disk path=/path/to/eyeon-debian12-amd64.qcow2,format=qcow2,bus=virtio \
  --os-variant debian12 \
  --network network=default,model=virtio \
  --graphics none \
  --console pty,target_type=serial
```

Useful follow-up commands:

```bash
virsh console eyeon-debian12-amd64
virsh domifaddr eyeon-debian12-amd64 --source arp
```

Detach from `virsh console` with `Ctrl + ]`.

## UTM (macOS)

Use the qcow2 as the VM disk.

Intel Mac:

- Prefer virtualization if your UTM build exposes direct disk import there.
- On some UTM 4.7.x builds, `Import Existing Drive` only appears under the `Emulate` flow.
- If UTM reports `bootindex=0 in use`, remove any extra kernel/initrd or installer media and leave only the imported qcow2 as the boot device.

Apple Silicon:

- Use the `arm64` qcow2 with virtualization for the best experience.
- The `amd64` qcow2 can be used for functional testing under emulation, but it is slow.

## Hyper-V (Windows)

Hyper-V does not use qcow2 directly. Convert to `vhdx` first.

```bash
qemu-img convert -p -f qcow2 -O vhdx eyeon-debian12-amd64.qcow2 eyeon-debian12-amd64.vhdx
```

Then:

1. Create a new Generation 2 VM.
2. Attach the converted `vhdx` as the boot disk.
3. Set at least 2 vCPU and 4 GB RAM.
4. Attach a DHCP-enabled virtual switch.

## VMware Workstation / ESXi

VMware does not use qcow2 directly. Convert to `vmdk` first.

```bash
qemu-img convert -p -f qcow2 -O vmdk eyeon-debian12-amd64.qcow2 eyeon-debian12-amd64.vmdk
```

Then create a new Linux VM and attach the converted `vmdk` as the boot disk.

## VirtualBox

VirtualBox is easiest if you convert to `vdi` first.

```bash
qemu-img convert -p -f qcow2 -O vdi eyeon-debian12-amd64.qcow2 eyeon-debian12-amd64.vdi
```

Then create a new Linux VM and attach the converted `vdi` as the primary disk.

## Notes

- The project currently ships qcow2 as the primary VM artifact.
- Nutanix AHV and libvirt/KVM are the most direct deployment paths.
- VMware, Hyper-V, and VirtualBox deployment paths are conversion-based and should be treated as convenience paths rather than the primary validated target.

## Optional NFS Workflow

The image includes NFS client tools, but NFS is optional and no export is
mounted automatically. Use the local quickstart after login for the complete
workflow. A deployment can instead use local storage, SCP, SSHFS, hypervisor
shared folders, or another site-specific transfer mechanism.

Typical manual client setup is:

```bash
sudo mkdir -p /mnt/scan-input /mnt/parse-output
showmount -e <nfs-server>  # may not work against NFSv4-only servers
sudo mount -t nfs -o vers=4 <nfs-server>:/<input-export> /mnt/scan-input
sudo mount -t nfs -o vers=4 <nfs-server>:/<output-export> /mnt/parse-output
eyeon-parse.sh UTIL_CD /mnt/scan-input /mnt/parse-output
sudo umount /mnt/scan-input /mnt/parse-output
```

Keep the active DuckDB database on local VM storage. An active DuckDB database
on NFS is future work requiring deliberate validation of locking and consistency
behavior.
