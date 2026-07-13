packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.0"
    }
  }
}

variable "debian_cloud_image_url" {
  type    = string
  default = "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
}

# NOTE: Provide this at build time with `-var debian_cloud_image_checksum=...`.
variable "debian_cloud_image_checksum" {
  type    = string
  default = ""
}

variable "eyeon_wheel" {
  type = string
}

variable "qemu_binary" {
  type    = string
  default = "qemu-system-x86_64"
}

variable "qemu_accelerator" {
  type    = string
  # On Linux, prefer KVM. On Apple Silicon, x86_64 builds require emulation.
  default = "kvm"
}

locals {
  output_dir = "builds/vm/output/debian12-amd64"
}

source "qemu" "debian12" {
  disk_image = true
  iso_url    = var.debian_cloud_image_url
  iso_checksum = var.debian_cloud_image_checksum

  output_directory = local.output_dir
  format           = "qcow2"

  qemu_binary = var.qemu_binary

  accelerator = var.qemu_accelerator

  headless  = true
  disk_size = "20G"

  # When emulating x86_64 on Apple Silicon (TCG), we need a CPU model that
  # advertises the instruction set extensions used by common Python wheels
  # (e.g. duckdb/pyarrow). Otherwise the guest can SIGILL during imports.
  qemuargs = [
    ["-cpu", "max"],
  ]

  boot_command = []
  boot_wait    = "5s"

  # Cloud-init seed ISO attached as a CD-ROM.
  cd_files = [
    "builds/vm/cloud-init/user-data",
    "builds/vm/cloud-init/meta-data",
  ]
  cd_label = "cidata"

  ssh_username = "debian"
  ssh_password = "debian"
  ssh_timeout  = "30m"

  shutdown_command = "echo 'debian' | sudo -S shutdown -P now"
}

build {
  sources = ["source.qemu.debian12"]

  provisioner "file" {
    source      = "builds/provision"
    destination = "/tmp/eyeon-provision"
  }

  provisioner "file" {
    source      = "../pEyeON-Analytics"
    destination = "/tmp/pEyeON-Analytics"
  }

  provisioner "file" {
    source      = var.eyeon_wheel
    destination = "/tmp/"
  }

  provisioner "shell" {
    # Debian cloud images default to /bin/sh for inline scripts; we need bash for
    # `set -o pipefail` and to match our provision scripts.
    inline_shebang = "/bin/bash -e"
    inline = [
      "set -euo pipefail",
      "sudo chmod -R a+rx /tmp/eyeon-provision",
      "sudo bash /tmp/eyeon-provision/install-build-deps-debian.sh",
      "sudo bash /tmp/eyeon-provision/install-cmake.sh",
      "sudo bash /tmp/eyeon-provision/build-tlsh.sh",
      "sudo bash /tmp/eyeon-provision/install-rust-binwalk.sh",
      "sudo install -m 0755 /root/.cargo/bin/binwalk /usr/local/bin/binwalk",
      "sudo bash /tmp/eyeon-provision/install-runtime-deps-debian-podman.sh",
      "sudo bash /tmp/eyeon-provision/install-sasquatch-deb.sh",

      # Ensure networking comes up on boot across hypervisors.
      "sudo bash /tmp/eyeon-provision/configure-dhcp-networkd.sh",
      "sudo mkdir -p /opt/eyeon",
      "sudo bash -lc 'wheel=$(ls -1 /tmp/peyeon-*.whl | head -1); test -f \"$wheel\"; bash /tmp/eyeon-provision/install-eyeon-venv.sh --venv /opt/eyeon/venv --wheel \"$wheel\"'",
      "sudo /opt/eyeon/venv/bin/surfactant plugin update-db --all || true",
      "sudo ln -sf /opt/eyeon/venv/bin/eyeon /usr/local/bin/eyeon",
      "sudo useradd -m -s /bin/bash -G sudo eyeon || true",
      "echo 'eyeon:eyeon' | sudo chpasswd",

      # Analytics environment (uv + locked deps).
      "sudo bash /tmp/eyeon-provision/install-uv.sh",
      "sudo rm -rf /opt/pEyeON-Analytics && sudo mv /tmp/pEyeON-Analytics /opt/pEyeON-Analytics",
      "sudo chown -R eyeon:eyeon /opt/pEyeON-Analytics",
      "sudo -u eyeon -H bash -lc 'uv python install 3.13'",
      "sudo -u eyeon -H bash -lc '/tmp/eyeon-provision/install-peyeon-analytics-uv.sh /opt/pEyeON-Analytics'",
    ]
  }
}
