## Code notes
 * The object cannot be destroyed .

## ownership notes
 * The two less interesting cases:

## DPDK notes
 * SPDK Ubuntu's DPDK package 

## Immediate TODOs
 * This list should be empty :)
 * read object workflow: handle request, read into object etc
 * write object worklfow: handle request, write into object etc
 * format the broken drives
 * use objects in http

## Short-term TODOs
 * key experiment tput/latency: read
 * key experiment tput/latency: append
 * key experiment tput/latency: target failure
 * key experiment tput/latency: gw failure
 * key experiment tput/latency: GC
 * key experiment tput/latency: checkpoint
 * Need to have a test for object
 * crafting map for recovery: two devices 
 * crafting map for read and writes
- [x] different object sizes
- [ ] some functional or correctness tests
- [ ] failure recover things 

## Long-term TODOs
 * read zone header broken, we should be able to read this and store the zones
   we need to write to in the future
 * Need to have a test for  overall system

## Longer-term TODOs
 * Need to have a test for 
