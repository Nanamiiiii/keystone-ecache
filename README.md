# Keystone with Enclave Cache

[![](https://systex-workshop.github.io/2025/img/systexbadges-available.svg)](https://systex-workshop.github.io/2025/artifact.html)
[![](https://systex-workshop.github.io/2025/img/systexbadges-functional.svg)](https://systex-workshop.github.io/2025/artifact.html)
[![](https://systex-workshop.github.io/2025/img/systexbadges-reusable.svg)](https://systex-workshop.github.io/2025/artifact.html)

## Getting Started
You can try on QEMU and HiFive Unmatched.

### Prerequisites
- Ubuntu and its flavors are recommended
- Install following required packages
  ```
  sudo apt update
  sudo apt install autoconf automake autotools-dev bc \
    bison build-essential curl expat jq libexpat1-dev flex gawk gcc git \
    gperf libgmp-dev libmpc-dev libmpfr-dev libtool texinfo tmux \
    patchutils zlib1g-dev wget bzip2 patch vim-common lbzip2 python3 \
    pkg-config libglib2.0-dev libpixman-1-dev libssl-dev screen \
    device-tree-compiler expect makeself unzip cpio rsync cmake ninja-build p7zip-full
  ```
    - Follow the [Buildroot Docs](https://buildroot.org/downloads/manual/manual.html#requirement)
    - Most of the build process is common to original Keystone. Referring [Keystone's Docs](http://docs.keystone-enclave.org) is useful.

### Build
1. Clone the repository.
   ```
   git clone https://github.com/Nanamiiiii/keystone-ecache.git -b systex-2025
   ```
2. Initialize submodules.
   ```
   git submodule update --init
   ```
3. Build System Image
    - QEMU
      ```
      make -j $(nproc)
      ```
    - HiFive Unmatched
      ```
      make KEYSTONE_PLATFORM=unmatched -j $(nproc)
      ```
4. Run Emulator or Flush Image
    - QEMU
      ```
      # Launch QEMU System Emulator
      make run
      ```
    - HiFive Unmatched
      ```
      # You can write the image to SD Card.
      make KEYSTONE_PLATFORM=unmatched DEVICE=/dev/sdX flush

      # Manual Write
      dd if=build-unmatched64/images/sdcard.img of=/dev/sdX iflag=fullblock oflag=direct conv=fsync status=progress
      ```
5. Execute Sample Application  
   You can login as `root` with password: `sifive`.
   ```
   # modprobe keystone_driver
   # cd /usr/share/keystone/examples
   # ./hello.ke
   ```
    - Cache Miss
      ```
      # ./hello.ke
      Verifying archive integrity... MD5 checksums are OK. All good.
      Uncompressing Keystone Enclave Package
      base ,size = 2199912448d, 2097152d
      miss
      size = 876544dbase ,size = 2199912448d, 2097152d
      hello, world!
      ```
    - Cache Hit
      ```
      # ./hello.ke
      Verifying archive integrity... MD5 checksums are OK. All good.
      Uncompressing Keystone Enclave Package
      base ,size = 2199912448d, 2097152d
      hit
      hello, world!
      ```

## Example Applications
We provide following example applications under `/usr/share/keystone/examples`.
- `hello.ke`
- `mea1.ke` - `mea8.ke`
- `aesserver.ke`
- `signserver.ke`
- `client`
- `aesclient`
- `signclient`

Self-extract packages (`*.ke`) include dummy certificate, publickey, and signature for the applications to test functionality.

### Launch Measurement
`mea1.ke` - `mea8.ke` measure the startup overhead per application size.
```
# ./mea1.ke
Verifying archive integrity... MD5 checksums are OK. All good.
Uncompressing Keystone Enclave Package
base ,size = 2199912448d, 2097152d
miss
size = 872448dbase ,size = 2199912448d, 2097152d
time = 0.772971sec.
```

### Digital Signature Program
`signserver.ke` is the server application to give a signature to the message from client application `signclient`.  
The signinig process is performed in the enclave.

```
# ./signserver.ke &
[1] 348
# Verifying archive integrity... MD5 checksums are OK. All good.
Uncompressing Keystone Enclave Package

# ./signclient
key_number0
client100000
host len100000
base ,size = 2199912448d, 2097152d
miss
size = 1220608dbase ,size = 2199912448d, 2097152d
enclave0.982282
send1.1767
length 100000
32Echo from server: 317066a8aa7364fe8dbde5ba71bd05f2766a93fff4c7f44edbc9792540b99205
return1.20196
Disconnected from server.
```
