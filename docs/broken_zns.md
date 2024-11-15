NVME Identify Namespace 2:
nsze    : 0x73400000
ncap    : 0x3c9b8800
nuse    : 0
nsfeat  : 0x6
  [4:4] : 0     NPWG, NPWA, NPDG, NPDA, and NOWS are Not Supported
  [3:3] : 0     NGUID and EUI64 fields if non-zero, Reused
  [2:2] : 0x1   Deallocated or Unwritten Logical Block error Supported
  [1:1] : 0x1   Namespace uses NAWUN, NAWUPF, and NACWU
  [0:0] : 0     Thin Provisioning Not Supported

nlbaf   : 4
flbas   : 0
  [6:5] : 0     Most significant 2 bits of Current LBA Format Selected
  [4:4] : 0     Metadata Transferred in Separate Contiguous Buffer
  [3:0] : 0     Least significant 4 bits of Current LBA Format Selected

mc      : 0x3
  [1:1] : 0x1   Metadata Pointer Supported
  [0:0] : 0x1   Metadata as Part of Extended Data LBA Supported

dpc     : 0x17
  [4:4] : 0x1   Protection Information Transferred as Last Bytes of Metadata Supported
  [3:3] : 0     Protection Information Transferred as First Bytes of Metadata Not Supported
  [2:2] : 0x1   Protection Information Type 3 Supported
  [1:1] : 0x1   Protection Information Type 2 Supported
  [0:0] : 0x1   Protection Information Type 1 Supported

dps     : 0
  [3:3] : 0     Protection Information is Transferred as Last Bytes of Metadata
  [2:0] : 0     Protection Information Disabled

nmic    : 0x1
  [0:0] : 0x1   Namespace Multipath Capable

rescap  : 0xff
  [7:7] : 0x1   Ignore Existing Key - Used as defined in revision 1.3 or later
  [6:6] : 0x1   Exclusive Access - All Registrants Supported
  [5:5] : 0x1   Write Exclusive - All Registrants Supported
  [4:4] : 0x1   Exclusive Access - Registrants Only Supported
  [3:3] : 0x1   Write Exclusive - Registrants Only Supported
  [2:2] : 0x1   Exclusive Access Supported
  [1:1] : 0x1   Write Exclusive Supported
  [0:0] : 0x1   Persist Through Power Loss Supported

fpi     : 0x80
  [7:7] : 0x1   Format Progress Indicator Supported
  [6:0] : 0     Format Progress Indicator (Remaining 0%)

dlfeat  : 8
  [4:4] : 0     Guard Field of Deallocated Logical Blocks is set to 0xFFFF
  [3:3] : 0x1   Deallocate Bit in the Write Zeroes Command is Supported
  [2:0] : 0     Bytes Read From a Deallocated Logical Block and its Metadata are Not Reported

nawun   : 31
nawupf  : 31
nacwu   : 0
nabsn   : 0
nabo    : 0
nabspf  : 0
noiob   : 0
nvmcap  : 7,919,919,693,824
mssrl   : 0
mcl     : 0
msrc    : 0
nulbaf  : 0
anagrpid: 0
nsattr  : 0
nvmsetid: 0
endgid  : 0
nguid   : 3c000000000000000014ee83021bbd01
eui64   : 0014ee83021bbd01

