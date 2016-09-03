# FileSystem-从系统调用角度看文件系统
 文件系统到底是什么？不妨看看文件系统在内核中的组织形式，参见文件系统.jpg
 
## 1 open系统调用
1.1	入口
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
	open系统调用标识；
	filename用户空间的路径名地址；
	flags标志位，比如打开方式、文件不存在时是否创建等；
	mode文件不存在需要创建文件的权限位。
1.2	主要功能实现
	调用force_o_largefile()判断是否支持大文件；
	调用build_open_flags设置不同的flags标志位，mode权限位，并整合成open_flags对象；
	调用getname分配一页内存，并根据用户态路径地址filename将路径名拷贝进内核；
	调用get_unused_fd_flags获得当前进程的可以使用的文件描述符fd；
	调用do_filp_open开始根据路径名查找到路径名的最后一个分量的父目录parent，根据父目录parent以及路径名最后一个分量通过目录项缓存找到最后一个分量的dentry。如果dentry是有效的，调用atomic_open打开文件；如果dentry是无效的，根据flags标识决定是否需要调用vfs_create创建文件。返回文件对象file；
	调用fsnotify_open通知父目录该文件已经打开；
	调用fd_install将当前进程的打开文件信息fd与file文件对象绑定；
	调用putname释放getname分配的内存；
	返回文件描述符fd。

## 2 close系统调用
2.1	入口
SYSCALL_DEFINE1(close, unsigned int, fd)
	fd需要关闭的文件的文件描述符
2.2	主要功能实现
	调用__close_fd将当前进程的fdtable的open_fds的fd位清0、将next_fd设置为fd。调用flush将文件内容写进磁盘。释放file文件对象上的锁

## 3 read系统调用
3.1	入口
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
	read系统调用标识
	fd文件描述符
	buf用户空间的缓冲区地址
	count一次读取的字节数
3.2	主要功能实现
	调用fdget将fd和根据fd获得的文件对象file绑定在fd结构体上，并将file文件对象的f_count加一；
	调用file_pos_read通过文件对象file获取当前文件的读取位置pos；
	调用rw_verify_area将file加锁，以及读权限检查；
	调用具体文件系统的read函数开始读取，并将读取内容放在buf上
	调用file_pos_write将文件对象的文件读取位置进行更新；
	调用fdput将文件对象的f_count减一
	返回读取成功的字节数

## 4 write系统调用
4.1	入口
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf, size_t, count)
	write系统调用标识；
	fd文件描述符
	buf用户态的缓冲区地址；
	count一次读取的字节数。
4.2	主要功能实现
	调用fdget将fd和根据fd获得的文件对象file绑定在fd结构体上，并将file文件对象的f_count加一；
	调用file_pos_read通过文件对象file获取当前文件的写位置pos；
	调用rw_verify_area将file加锁，以及写权限检查；
	调用具体文件系统的write函数开始写，返回写成功的字节数
	调用file_pos_write将文件对象的位置进行更新；
	调用fdput将文件对象的f_count减一
	返回写成功的字节数。
4.3	详细实现过程
i.	调用fdget(fd)
函数原型： static inline struct fd fdget(unsigned int fd)
参数： 文件描述符fd
数据对象： 文件对象file，当前进程current
功能： 通过fd获得文件对象fd
数据对象变化： 通过current->files获得文件的打开文件信息files（files_struct类型），原子判断files->count是否为1，如果为1，说明没有进程共享该files，那么文件对象file通过files->fdt->fd[fd]得到，同时fput_needed等于0，用于fdput判断是否需要释放文件对象file；如果为0，说明有进程共享该files，加rcu锁，文件对象file通过files->fdt->fd[fd]得到，如果file->f_mode标志位没有FMODE_PATH（说明open的时候并没有真正打开文件只是获得fd），将file->f_count引用加1，并且fput_needed等于1，在写结束之后释放文件对象。
ii.	调用file_pos_read(f.file)
函数原型：static inline loff_t file_pos_read(struct file *file)
参数： 文件对象file
数据对象： 文件对象file
功能： 通过文件对象获取文件位置
数据对象变化： 直接返回file->f_pos
iii.	调用vfs_write(f.file, buf, count, &pos)
函数原型： ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
参数： 文件对象file，用户态缓冲区地址buf，写入字节数count，写入位置pos
数据对象： 文件对象file，文件inode节点，当前进程current，目录项dentry，超级块superblock
功能： 将用户态缓冲区buf的内容写入文件
数据对象变化： 
	字段检查：判断file->f_mode是否有FMODE_WRITE允许写入权限；判断file->f_op->write以及file->f_op->aio_write是否定义了读取函数；判断是否可以对缓冲区读取
	调用rw_verify_area(WRITE, file, pos, count)：通过file获取文件inode节点；检查pos以及count字段是否合法；判断是否有冲突的锁；调用LSM模块的file_permission(file, mask)进行权限检查；调用fsnotify_parent(path, NULL, fsnotify_mask)通知父目录
	调用file_start_write(file)： 将超级块superblock的s_writers[SB_FREEZE_WRITE]加一
	调用具体文件系统的write函数开始写过程，具体函数为do_sync_write(file, buf, count, pos)： 该函数单独拿出来分析
iv.	do_sync_write(file, buf, count, pos)
函数原型： ssize_t do_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
参数： 文件对象file，用户空间缓存地址buf，写入的字节数len，文件写入位置ppos
数据对象： 文件对象file，当前的进程current，超级块super_block
功能： 写文件具体函数
数据对象变化：
	将用户空间缓存地址buf与写入字节数len封装在iovec类型的对象iov里面
	根据文件对象file以及当前的进程初始化一个kiocb类型的对象kiocb，其中ki_ctx = NULL，ki_filp = filp，ki_obj.tsk = current，ki_pos = *ppos，ki_nbytes = len
 
	调用aio_write(&kiocb, &iov, 1, kiocb.ki_pos)进行异步写，在EXT4文件系统中调用static ssize_t ext4_file_write(struct kiocb *iocb, const struct iovec *iov, unsigned long nr_segs, loff_t pos)：1. 通过iocb->ki_filp获得文件的inode节点；2. 判断inode是否有EXT4_INODE_EXTENTS标识，如果不含有该标志，则EXT4采用传统的块映射方式存储文件，此时文件大小受到超级块的s_bitmap_maxbytes大小限制，进行参数调整；3. 判断文件对象file的f_flags是否有O_DIRECT标识，如有调用ext4_file_dio_write(iocb, iov, nr_segs, pos)，否则调用generic_file_aio_write(iocb, iov, nr_segs, pos)，这两个函数分别分析
v.	ext4_file_dio_write(iocb, iov, nr_segs, pos)
函数原型： static ssize_t ext4_file_dio_write(struct kiocb *iocb, const struct iovec *iov, unsigned long nr_segs, loff_t pos)
参数： 内核IO控制块kiocb，封装用户态缓冲的iovec类型结构，要写的段数，写文件的位置pos
数据对象： 文件对象file，文件索引节点inode
功能： EXT4文件系统DIRECT IO写文件具体函数
数据对象变化：
	如果inode具有EXT4_INODE_EXTENTS标志且iocb具有同步标志，调用ext4_unaligned_aio(inode, iov, nr_segs, pos)： 
vi.	generic_file_aio_write(iocb, iov, nr_segs, pos)

