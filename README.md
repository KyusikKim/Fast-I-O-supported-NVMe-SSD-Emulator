# Fast-I-O-supported-NVMe-SSD-Emulator
- Main author: Kyusik Kim <kks@kw.ac.kr> <sswlab.kw.ac.kr>
----
## emulator directory 
- Forked repo: [FEMU] <https://github.com/ucare-uchicago/femu>
- Features
  - Supports host memory buffer of NVMe
  - Supports shared host memory buffer of NVMe (proposed)
  - Supports store NAND data to host storage (./data directory) when executing
  - Supports restore NAND data from host storage (./data directory) when terminating
  - Supports Fast I/O
## linux-4.13.10 directory
- Overwrite contained files if you want to enable Fast I/O on the host

