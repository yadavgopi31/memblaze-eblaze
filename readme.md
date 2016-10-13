File system of linux

• Linux retain unix standard file system mode .

• The linux kernel handles all types of file by hiding the

implementation details of any single file type behind a layer of

software called vfs [virtual file system].

• It has 2 component viz

a) A set of defination that specify what is file system object

are allowed to look .

b) A layer of software to manipulate the objects.

• The vfs have 4 component

a) An inode object

b) A file object

c) A superblock

d) A dentry object
