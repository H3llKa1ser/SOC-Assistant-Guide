# Memory Dump Creation

### Steps:

#### 1) Take a screenshot of the VM we want to dump the memory on

#### 2) Use vmss2core to create a .vmem file for analysis

    vmss2core -W {snampshot.vmss} {new name of dump.vmem}  

