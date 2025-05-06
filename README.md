# Keystone with Enclave Cache

## Getting Started
You can try on QEMU and HiFive Unmatched.

### Prerequisites
- Ubuntu and its flavors are recommended
- Install required packages by Buildroot
    - Follow the [Buildroot Docs](https://buildroot.org/downloads/manual/manual.html#requirement)
- Most of the build process is common to original Keystone. Please refer [Keystone's Docs](http://docs.keystone-enclave.org).

### Build
1. Clone the repository.
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
4. Run
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

### Example Applications
We have following example applications under `/usr/share/keystone/examples`.
- `hello`
- `mea*`
- `aes`
- `aesserver`
- `deaesserver`
- `singserver`
- `socket`
- `clients`