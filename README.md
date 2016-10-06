# FileSystem-从系统调用角度看文件系统
 文件系统到底是什么？不妨看看文件系统在内核中的组织形式，参见文件系统.jpg，如下图
 ![](文件系统.jpg)
 
1	open系统调用<br>
1.1	入口<br>
SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)<br>
	open系统调用标识；<br>
	filename用户空间的路径名地址；<br>
	flags标志位，比如打开方式、文件不存在时是否创建等；<br>
	mode文件不存在需要创建文件的权限位。<br>
1.2	主要功能实现<br>
	调用force_o_largefile()判断是否支持大文件；<br>
	调用build_open_flags设置不同的flags标志位，mode权限位，并整合成open_flags对象；<br>
	调用getname分配一页内存，并根据用户态路径地址filename将路径名拷贝进内核；<br>
	调用get_unused_fd_flags获得当前进程的可以使用的文件描述符fd；<br>
	调用do_filp_open开始根据路径名查找到路径名的最后一个分量的父目录parent，根据父目录parent以及路径名最后一个分量通过目录项缓存找到最后一个分量的dentry。如果dentry是有效的，调用atomic_open打开文件；如果dentry是无效的，根据flags标识决定是否需要调用vfs_create创建文件。返回文件对象file；<br>
	调用fsnotify_open通知父目录该文件已经打开；<br>
	调用fd_install将当前进程的打开文件信息fd与file文件对象绑定；<br>
	调用putname释放getname分配的内存；<br>
	返回文件描述符fd。<br><br>

2	close系统调用<br>
2.1	入口<br>
SYSCALL_DEFINE1(close, unsigned int, fd)<br>
	fd需要关闭的文件的文件描述符<br>
2.2	主要功能实现<br>
	调用__close_fd将当前进程的fdtable的open_fds的fd位清0、将next_fd设置为fd。调用flush将文件内容写进磁盘。释放file文件对象上的锁<br><br>

3	read系统调用<br>
3.1	入口<br>
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)<br>
	read系统调用标识<br>
	fd文件描述符<br>
	buf用户空间的缓冲区地址<br>
	count一次读取的字节数<br>
3.2	主要功能实现<br>
	调用fdget将fd和根据fd获得的文件对象file绑定在fd结构体上，并将file文件对象的f_count加一；<br>
	调用file_pos_read通过文件对象file获取当前文件的读取位置pos；<br>
	调用rw_verify_area将file加锁，以及读权限检查；<br>
	调用具体文件系统的read函数开始读取，并将读取内容放在buf上<br>
	调用file_pos_write将文件对象的文件读取位置进行更新；<br>
	调用fdput将文件对象的f_count减一<br>
	返回读取成功的字节数<br><br>

4	write系统调用<br>
4.1	入口<br>
SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf, size_t, count)<br>
	write系统调用标识；<br>
	fd文件描述符<br>
	buf用户态的缓冲区地址；<br>
	count一次读取的字节数。<br>
4.2	主要功能实现<br>
	调用fdget将fd和根据fd获得的文件对象file绑定在fd结构体上，并将file文件对象的f_count加一；<br>
	调用file_pos_read通过文件对象file获取当前文件的写位置pos；<br>
	调用rw_verify_area将file加锁，以及写权限检查；<br>
	调用具体文件系统的write函数开始写，返回写成功的字节数<br>
	调用file_pos_write将文件对象的位置进行更新；<br>
	调用fdput将文件对象的f_count减一<br>
	返回写成功的字节数。<br>
4.3	详细实现过程<br>
4.3.1	 fdget(fd)<br>
函数原型： static inline struct fd fdget(unsigned int fd)<br>
参数： 文件描述符fd<br>
数据对象： <br>
	current->files->count<br>
	current->files->fdt->fd[fd]<br>
	current->files->fdt->fd[fd]->f_mode<br>
	current->files->fdt->fd[fd]->f_count<br>
功能： 通过fd获得文件对象file<br>
数据对象变化： <br>
	如果current->files->count == 1<br>
fd.file = current->files->fdt->fd[fd];<br>
fd.need_put = 0<br>
return fd;<br>
	如果current->files->count != 1 && (current->files->fdt->fd[fd]->f_mode & FMODE_PATH == 0)<br>
fd.file = current->files->fdt->fd[fd];<br>
fd.need_put = 1<br>
return fd;<br>
	如果current->files->count != 1 && (current->files->fdt->fd[fd]->f_mode & FMODE_PATH == 1)<br>
fd.file = NULL;<br>
fd.need_put = 0;<br>
return fd;<br>
4.3.2	 file_pos_read(f.file)<br>
函数原型：static inline loff_t file_pos_read(struct file *file)<br>
参数： 文件对象file<br>
数据对象： <br>
	file<br>
功能： 通过文件对象获取文件位置<br>
数据对象变化： <br>
	return file->f_pos;<br>
4.3.3	 vfs_write(f.file, buf, count, &pos)<br>
函数原型： ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)<br>
参数： 文件对象file，用户态缓冲区地址buf，写入字节数count，写入位置pos<br>
数据对象： <br>
	file<br>
	superblock<br>
	file->f_inode<br>
	file_lock<br>
	current->files<br>
	current->tgid<br>
	blocked_hash<br>
	current<br>
	__wait_queue_head<br>
功能： 将用户态缓冲区buf的内容写入文件<br>
数据对象变化： <br>
	如果file->f_mode & FMODE_WRITE == 0<br>
return –EBADF;<br>
	如果!file->f_op->write && !file->f_op->aio_write，即文件系统未定义写函数<br>
return -EINVAL;<br>
	调用ret = rw_verify_area(WRITE, file, pos, count)：判断是否有冲突的锁；调用LSM模块的file_permission(file, mask)进行权限检查<br>
	如果ret >=0<br>
调用file_start_write(file)；<br>
ret = do_sync_write(file, buf, count, pos)；<br>
	如果ret > 0<br>
fsnotify_modify(file);<br>
add_wchar(current, ret);<br>
		inc_syscw(current);<br>
		file_end_write(file);<br>
		return ret<br>
	如果ret < 0<br>
return ret;<br>
 
4.3.3.1	rw_verify_area(WRITE, file, pos, count)<br>
函数原型： int rw_verify_area(int read_write, struct file *file, const loff_t *ppos, size_t count)<br>
参数： 文件对象file，写入文件位置ppos，写入字节数count<br>
数据对象： 文件对象file，当前的进程current<br>
	file<br>
	inode<br>
	inode->i_flock<br>
	current<br>
	file_lock<br>
	current->files<br>
	current->tgid<br>
	__wait_queue_head<br>
功能： 判断是否有冲突的写锁，LSM模块进行安全检查<br>
数据对象的变化：<br>
	inode = file->f_inode; retval = -EINVAL;<br>
	如果count < 0，即写入字节小于0<br>
return retval;<br>
	如果count >= 0 && *ppos < 0，即写入文件位置小于0<br>
	如果file->f_mode & FMODE_UNSIGNED_OFFSET == 0，即文件系统未采用无符号偏移量<br>
return retval;<br>
	如果count >= -pos && file->f_mode & FMODE_UNSIGNED_OFFSET != 0<br>
return -EOVERFLOW;<br>
	如果count >= 0 && *ppos >= 0<br>
	如果(*ppos + count) < 0，写入完成之后超过无符号长整形能表示的最大数<br>
	如果file->f_mode & FMODE_UNSIGNED_OFFSET == 0<br>
return retval;<br>
	如果(*ppos + count) >= 0 && inode->i_flock && ((inode)->i_sb->s_flags & (MS_MANDLOCK))，即写入位置以及字节无误且文件支持加强制锁
调用retval = locks_mandatory_area(read_write == READ ? FLOCK_VERIFY_READ : FLOCK_VERIFY_WRITE,inode, file, pos, count);<br>
	如果retval < 0<br>
return retval;<br>
retval = security_file_permission(file,read_write == READ ? MAY_READ : MAY_WRITE);<br>
	如果retval != 0<br>
return retval;<br>
return count > MAX_RW_COUNT ? MAX_RW_COUNT : count;<br>

4.3.3.1.1	locks_mandatory_area(read_write == READ ? FLOCK_VERIFY_READ : FLOCK_VERIFY_WRITE, inode, file, pos, count)<br>
函数原型： int locks_mandatory_area(int read_write, struct inode *inode, struct file *filp, loff_t offset, size_t count)<br>
参数： 读写标识read_write，文件inode，文件对象file，文件位置offset，判断的字节数<br>
数据对象： 文件索引节点inode，文件对象file，当前进程current<br>
	inode<br>
	file_lock<br>
	current->files<br>
	current->tgid<br>
	file<br>
	current<br>
	__wait_queue_head<br>
功能： 判断是否有冲突的锁<br>
数据对象的变化：<br>
	分配一把file_lock类型的文件锁fl，并初始化。<br>
	进入循环：<br>
	调用error = __posix_lock_file(inode, &fl, NULL)判断该inode节点上是否有和fl锁冲突的锁；<br>
	如果error != FILE_LOCK_DEFERRED，即上一个函数返回值显示文件没有死锁<br>
return error<br>
	如果error == FILE_LOCK_DEFERRED，即出现死锁<br>
调用error = wait_event_interruptible(fl.fl_wait, !fl.fl_next)，该锁指向的等待队列等待!fl.fl_next事件或者有信号需要处理。<br>
	error == 0，即!fl.fl_next事件发生或接收到信号，进程被唤醒<br>
	如果(ino->i_mode & (S_ISGID | S_IXGRP)) == S_ISGID，即判断文件的权限可以设置组ID并且没有组执行权限<br>
continue，继续循环加锁<br>
	error != 0 && (ino->i_mode & (S_ISGID | S_IXGRP)) ！= S_ISGID<br>
删除文件锁fl;<br>
break退出循环<br>
	return error<br>
4.3.3.1.1.1	__posix_lock_file(inode, &fl, NULL)<br>
函数原型： static int __posix_lock_file(struct inode *inode, struct file_lock *request, struct file_lock *conflock)<br>
参数： 文件inode节点，文件锁结构file_lock，复制一把锁conflock（写过程中为nulll）<br>
数据对象： <br>
	inode<br>
	file_lock<br>
	blocked_hash<br>
功能： 在读写过程中只需要找到是否有冲突的锁，如果有冲突返回错误码，返回0<br>
数据对象的变化：<br>
	error = 0<br>
	如果request->fl_type != F_UNLCK，F_UNLCK表示不加锁，该条件下fl表示inode上已经存在的锁，request表示申请的锁<br>
从inode->i_flock指向的锁链表的起始节点开始遍历整个链表，分别做如下检查：<br>
	fl->fl_flags & FL_POSIX == 0<br>
continue遍历下一个节点<br>
	分别做如下判断：fl->fl_flags & FL_POSIX ！=0 并且（request->fl_flags & FL_POSIX || request->fl_owner == fl->fl_owner），即都是POSIX锁且他们的owner相同，则没有冲突；两把锁的范围没有交集，则没有冲突；两把锁有交集但是两把锁都不是写锁，则没有冲突
没有冲突则continue遍历下一个节点<br>
	如果有冲突<br>
调用posix_locks_deadlock(request, fl)进行死锁检测，该函数返回0或者1：<br>
	当返回值为0，表示有死锁<br>
error = FILE_LOCK_DEFERRED<br>
调用__locks_insert_block(fl, request)<br>
	如果返回值为1，表示没有死锁，但是有可能发生死锁<br>
error = -EDEADLK<br>
return error<br>
	返回error。写过程只会判断到这里，函数接下来的锁调整不会去执行。<br>
4.3.3.1.1.2	wait_event_interruptible(fl.fl_wait, !fl.fl_next)<br>
说明： 当上一函数返回结果并非FILE_LOCK_DEFERRED（具有死锁），进入该宏<br>
函数原型： 该定义为宏定义<br>
参数： 文件锁的阻塞队列fl_wait<br>
数据对象：<br>
	fl_wait<br>
	fl.fl_next<br>
	current<br>
功能： 等待!fl.fl_next ！= 0唤醒进程或者进程接到中断信号<br>
数据对象的变化：<br>
	初始化一个等待队列项__wait，等待队列项用于保存阻塞进程以及唤醒函数；<br>
	进入无限循环；<br>
	调用prepare_to_wait_event，设置等待队列项字段，将进程状态设置为TASK_INTERRUPTIBLE，将等待队列项加入等待队列头指向的等待队列中。返回值__int为0表示将进程成功挂起；返回值为-ERESTARTSYS表示进程需要处理信号，处理完信号重新执行系统调用<br>
	!fl.fl_next != 0，即冲突锁解除，满足进程唤醒条件，退出循环<br>
	!fl.fl_next == 0，调用schedule()进行进程调度<br>
	调用finish_wait(&wq, &__wait)，设置进程状态TASK_RUNNING，将等待队列项从等待队列中移除<br>
4.3.3.1.1.3	locks_delete_block(&fl)<br>
函数原型：static void locks_delete_block(struct file_lock *waiter)<br>
参数：文件锁结构file_lock类型对象waiter<br>
数据对象：<br>
	文件锁file_lock<br>
功能：删除一把锁<br>
数据对象变化：<br>
	对blocked_lock_lock加自旋锁；<br>
	将waiter->fl_link从全局锁链表（通过hlist_node结构链接）中删除；<br>
	将waiter->fl_block从所有等待该锁的锁链表（通过list_head）中删除；<br>
	将waiter->next = NULL，表示从该文件索引节点i_flock指向的单链表中删除；<br>
	对blocked_lock_lock解自旋锁。<br>
4.3.3.1.2	security_file_permission(file,read_write == READ ? MAY_READ : MAY_WRITE)<br>
4.3.3.2	file_start_write(file)<br>
函数原型：static inline void file_start_write(struct file *file)<br>
参数：文件对象file<br>
数据对象：<br>
	file<br>
	superblock<br>
	percpu_counter<br>
功能：判断文件系统等级（未冻结、冻结写、冻结页缺失、冻结、完全冻结），并将写者加一，该等级与文件系统快照有关，具体作用不详<br>
数据对象变化：<br>

4.3.3.2.1	__sb_start_write(file_inode(file)->i_sb, SB_FREEZE_WRITE, true)<br>
4.3.3.3	do_sync_write(file, buf, count, pos)<br>
函数原型： ssize_t do_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)<br>
参数： 写入的字节数len，文件写入位置ppos<br>
数据对象： <br>
	file<br>
	current<br>
	super_block<br>
功能： 写文件具体函数<br>
数据对象变化：<br>
	将用户空间缓存地址buf与写入字节数len封装在iovec类型的对象iov里面<br>
	根据文件对象file以及当前的进程初始化一个kiocb类型的对象kiocb，其中ki_ctx = NULL，ki_filp = filp，ki_obj.tsk = current，ki_pos = *ppos，ki_nbytes = len<br>
 
	调用aio_write(&kiocb, &iov, 1, kiocb.ki_pos)进行异步写，在EXT4文件系统中调用static ssize_t ext4_file_write(struct kiocb *iocb, const struct iovec *iov, unsigned long nr_segs, loff_t pos)：通过iocb->ki_filp获得文件的inode节点；2. 判断inode是否有EXT4_INODE_EXTENTS标识，如果不含有该标志，即ext4_inode_info.i_flags & EXT4_INODE_EXTENTS == 0，则EXT4采用传统的块映射方式存储文件，此时文件大小受到超级块的s_bitmap_maxbytes大小限制，进行参数调整；3. 判断文件对象file的f_flags是否有O_DIRECT标识，如有调用ext4_file_dio_write(iocb, iov, nr_segs, pos)，否则调用generic_file_aio_write(iocb, iov, nr_segs, pos)，这两个函数分别分析<br>
4.3.3.3.1	init_sync_kiocb(&kiocb, filp)<br>
函数原型： static inline void init_sync_kiocb(struct kiocb *kiocb, struct file *filp)<br>
参数： 内核IO控制块kiocb结构，文件对象file<br>
数据对象： 当前进程current，文件对象file<br>
功能：初始化内核IO控制块kiocb<br>
数据对象的变化：<br>
	kiocb.ki_ctx = NULL<br>
	kiocb.ki_filp = filp<br>
	kiocb.ki_obj.tsk = current<br>
4.3.3.3.2	aio_write(&kiocb, &iov, 1, kiocb.ki_pos)<br>
函数原型：static ssize_t ext4_file_write(struct kiocb *iocb, const struct iovec *iov, unsigned long nr_segs, loff_t pos)<br>
参数： 内核io控制块，封装了用户态缓冲区的iovec结构，nr_segs = 1，写入文件位置<br>
数据对象：<br>
	inode<br>
	file<br>
	ext4_sb_info<br>
	ext4_inode_info<br>
功能： 异步读<br>
数据对象的变化：<br>
	通过iocb获得文件的inode节点，inode = iocb->ki_filp-f_inode；<br>
	如果文件ext4_inode_info.i_flags不具有EXT4_INODE_EXTENTS标识(文件是通过传统的间接映射的方式布局)。此时文件大小受到ext4_sb_info-> s_bitmap_maxbytes限制。通过文件的inode节点获得ext4文件系统超级块（内存），ext4_sb_info = inode->i_sb->s_fs_info；通过ext4_sb_info-> s_bitmap_maxbytes判断文件写入位置是否超过文件最大大小，如果文件写入位置加上文件的写入字节是否超过文件的最大大小，如果是，则调整文件的写入大小<br>
	如果iocb->ki_filp->flags & O_DIRECT != 0，调用ret = ext4_file_dio_write(iocb, iov, nr_segs, pos)进行直接IO操作<br>
	如果iocb->ki_filp->flags & O_DIRECT == 0，调用ret = generic_file_aio_write(iocb, iov, nr_segs, pos);<br>
	返回ret<br>
4.3.3.3.2.1	ext4_file_dio_write(iocb, iov, nr_segs, pos)<br>
函数原型： static ssize_t ext4_file_dio_write(struct kiocb *iocb, const struct iovec *iov, unsigned long nr_segs, loff_t pos)<br>
参数： 内核IO控制块kiocb，封装用户态缓冲的iovec类型结构，要写的段数，写文件的位置pos<br>
数据对象： <br>
	文件对象file<br>
	文件索引节点inode<br>
	dentry<br>
	super_block<br>
	ext4_sb_info<br>
	current<br>
	wait_queue_head_t<br>
	wait_queue_t<br>
	blk_plug<br>
	ext4_map_blocks<br>
	ext4_es_tree<br>
	extent_status<br>
	rb_node<br>
	ext4_ext_path<br>
	ext4_extent<br>
	ext4_allocation_request<br>
	ext4_io_end_t<br>
	buffer_head<br>
	Indirect<br>
	block_device<br>
	init_user_ns<br>
	ext4_xattr_ibody_header<br>
	ext4_xattr_entry<br>
	ext4_inode<br>
	ext4_iloc<br>
	ext4_xattr_cache<br>
功能： EXT4文件系统DIRECT IO写文件具体函数<br>
数据对象变化：<br>
	如果ext4_inode_info.i_flags & EXT4_INODE_EXTENTS != 0且iocb->ki_ctx == NULL，调用unaligned_aio = ext4_unaligned_aio(inode, iov, nr_segs, pos)判断是否块对齐<br>
	如果unaligned_aio != 0(块未对齐)，DIRECT AIO必须串行方式读取，调用ext4_unwritten_wait(inode)通过inode初始化一个ioend等待队列，将当前进程挂起在该等待队列上，等待事件ext4_inode_info.i_unwritten == 0发生之后唤醒进程<br>
	对inode->i_mutex加锁<br>
	调用blk_start_plug(&plug)，将IO请求存放在current->plug中，方便将很多小的IO请求合并成大的IO请求<br>
	如果ext4_should_dioread_nolock(inode) && !unaligned_aio && !file->f_mapping->nrpages && pos + length <= i_size_read(inode)，即依次做如下判断：<br>
	ext4_sb_info->s_mount_opt & EXT4_MOUNT_DIOREAD_NOLOCK != 0；（检查文件挂载标识）<br>
inode->i_mode & S_IFMT == S_IFREG；（检查是否为普通文件）<br>
ext4_inode_info->i_flags & EXT4_INODE_EXTENTS != 0；（检查是否为extents映射）<br>
ext4的日志模式为JOURNAL模式（分别有JOURNAL模式、ORDERED模式、WRITEBACK模式）；<br>
!unaligned_aio；（块对齐）<br>
!file->f_mapping->nrpages；（块未缓冲）<br>
pos + length <= i_size_read(inode)；（写后未超过文件长度）<br>
	如果上述条件都满足，进行DIO写覆盖：<br>
1.	声明ext4_map_blocks结构的map对象，表示逻辑块与物理块的映射；<br>
2.	map.m_lblk = pos >> blkbits;要写的位置所在的逻辑块号<br>
3.	map.m_len = (EXT4_BLOCK_ALIGN(pos + length, blkbits) >> blkbits)- map.m_lblk;要写的块数，其中有块对齐操作<br>
4.	调用err = ext4_map_blocks(NULL, inode, &map, 0)：<br>
a)	声明extent_status结构体的对象es，该结构字段rb_node红黑树节点，es_lblk第一个逻辑块号，es_len逻辑块数，es_pblk第一个物理块号<br>
b)	参数检查；<br>
c)	调用ext4_es_lookup_extent(inode, map->m_lblk, &es)，从ext4_inode_info-> i_es_tree指向的extent方式红黑树根节点找到是否已经建立物理块到逻辑块的映射（先从extent_status缓存开始找，如果找到，返回1,。没有找到从root开始按照二叉搜索树的方式找，找到返回1，没有找到返回0）；<br>
 
	如果函数返回值为1。说明逻辑块与物理块已经建立了映射，计算建立的块数<br>
	如果函数返回值为0。说明逻辑块没有与物理块建立映射，调用down_read((&EXT4_I(inode)->i_data_sem))对信号量进行P操作。<br>
	如果ext4_inode_info->i_flag & EXT4_INODE_EXTENTS ！= 0，即采用extent方式，调用retval = ext4_ext_map_blocks(handle, inode, map, flags & EXT4_GET_BLOCKS_KEEP_SIZE)，该函数总共400行代码，作用是建立物理块与逻辑块映射。<br>
	如果ext4_inode_info->i_flag & EXT4_INODE_EXTENTS == 0，即采用传统索引块映射方式，调用ext4_ind_map_blocks(handle, inode, map, flags & EXT4_GET_BLOCKS_KEEP_SIZE)：<br>
i.	计算每个磁盘块大小，ptrs = inode->i_sb->s_blocksize / sizeof(__u32)；<br>
ii.	计算每个磁盘块占的位数，ptrs_bits = inode->i_sb->s_fs_info-> s_addr_per_block_bits<br>
iii.	计算一级间址占用掉的索引磁盘块号数目，indirect_blocks = ptrs；<br>
iv.	计算二级间址占用掉的索引磁盘块号数目，double_blocks = (1 << (ptrs_bits * 2))<br>
v.	声明depth变量表示map中的逻辑块采用的映射方式，1表示直接映射，2表示一级间址，3表示二级间址，4表示三级间址；<br>
vi.	如果depth > 1，获得depth – 1个缓冲区首部（非常复杂的操作，主要包含操作本CPU的LRU、禁止中断、禁止内核抢占、块设备基树操作、内存不足时脏页写回、启动写回线程、进程调度），这些缓冲区首部用来一级间址、二级间址、三级间址的物理块与逻辑块的映射。如果获取失败，直接返回-ENOMEM<br>
vii.	建立物理块与逻辑块映射（depth等于1是为直接映射，可以直接从逻辑块获取物理块，不需要建立映射）。vi步获得的缓冲区首部是从块设备基树直接获得的，为物理块。令map->m_pblk = le32_to_cpu(chain[depth-1].key)<br>
viii.	第vii为简单情况下的建立映射方式，有可能map->m_lblk为直接索引，但是map->m_lblk + map->m_len为一级间址，这种情况建立映射很复杂。<br>
	调用up_write((&EXT4_I(inode)->i_data_sem))对信号量进行V操作<br>
d)	返回建立映射的磁盘块数<br>
	如果上述条件不都满足，调用ret = __generic_file_aio_write(iocb, iov, nr_segs, &iocb->ki_pos)，具体执行写操作的函数主体：<br>
1.	调用err = generic_segment_checks(iov, &nr_segs, &ocount, VERIFY_READ)进行常规字段检查；<br>
2.	current->backing_dev_info = mapping->backing_dev_info，用作脏页写回；<br>
3.	调用err = generic_write_checks(file, &pos, &count, S_ISBLK(inode->i_mode))同样为常规字段检查，涉及全局变量current；<br>
4.	调用err = file_remove_suid(file)将文件的suid清0。<br>
	调用killsuid = should_remove_suid(dentry)<br>
i.	初始化kill = 0，用来标记需要清除的权限位<br>
ii.	如果dentry->d_inode->i_mode & S_ISUID != 0，kill = ATTR_KILL_SUID<br>
iii.	如果（dentry->d_inode->i_mode & S_ISGID）&& （dentry->d_inode->i_mode & S_IXGRP），kill |= ATTR_KILL_SGID<br>
iv.	如果kill && !capable(CAP_FSETID) && S_ISREG(mode)，返回kill。其中capable(CAP_FSETID)为权能位判断，涉及全局变量current、init_user_ns<br>
v.	如果iv条件不成立，返回0<br>
	调用killpriv = security_inode_need_killpriv(dentry)，检查是否需要擦除特殊权限<br>
i.	如果！inode->i_op->gettxattr，返回0；<br>
ii.	否则，调用error = inode->i_op->getxattr(dentry, XATTR_NAME_CAPS, NULL, 0)，返回值为名字为XATTR_NAME_CAPS的扩展属性的长度或者错误码，该函数的调用过程：<br>
a)	handler = xattr_resolve_name(dentry->d_sb->s_xattr, &name)分发<br>
b)	handler->get(dentry, name, NULL, 0, handler->flags) ,ext4通过分发handler机制get函数分发到ext4_xattr_security_get<br>
	down_read(&EXT4_I(dentry->d_inode)->xattr_sem)操作系统中的P操作<br>
首先通过inode空闲空间获取扩展属性<br>
	error = ext4_get_inode_loc(inode, &iloc)根据inode号找到inode所在的组描述符、块、块偏移量<br>
	raw_inode = ext4_raw_inode(&iloc)获得inode<br>
	header = IHDR(inode, raw_inode)获得扩展属性头<br>
	entry = IFIRST(header)找到第一个扩展属性节点<br>
	end = (void *)raw_inode + EXT4_SB(inode->i_sb)->s_inode_size计算inode占用的结束内存地址，这样从entry开始一直到end都是扩展属性节点<br>
	error = ext4_xattr_check_names(entry, end, entry)从entry到end检索所有的扩展属性节点字段是否合法<br>
	error = ext4_xattr_find_entry(&entry, name_index, name, end - (void *)entry, 0)<br>
从entry到最后一个扩展属性节点，分别比较扩展属性前缀、扩展属性名长度、扩展属性名，找到名字为name的扩展属性，这里的name为上层函数传递过来的XATTR_NAME_CAPS<br>
如果error = -ENODATA即没有获取到数据，那么需要从具体的物理块获取数据，进行如下步骤：<br>
	bh = sb_bread(inode->i_sb, EXT4_I(inode)->i_file_acl)从ext4_inode_info-> i_file_acl找到指向存储扩展属性的物理块号，从CPU的LRU分配缓冲区头，与物理块号建立映射关系，具体上文已经分析，其中涉及current、进程调度等<br>
	ext4_xattr_check_block(inode, bh)参数检查<br>
	ext4_xattr_cache_insert(bh)从全局ext4_xattr_cache扩展属性缓冲区新建一个节点并用装有扩展属性的缓冲区头初始化该节点<br>
	entry = BFIRST(bh)根据装有扩展属性的缓冲区头获取第一个扩展属性节点<br>
	error = ext4_xattr_find_entry(&entry, name_index, name, bh->b_size, 1)同上文分析<br>
	up_read(&EXT4_I(dentry->d_inode)->xattr_sem)操作系统中的V操作<br>
iii.	如果error <= 0，返回0；否则，返回1<br>
	如果killpriv > 0，调用error = security_inode_killpriv(dentry)擦除扩展属性<br>
i.	如果!inode->i_op->removexattr，返回0；<br>
ii.	否则，进行扩展属性的擦除， dentry->d_inode->i_op->removexattr (dentry, XATTR_NAME_CAPS)，函数调用过程：<br>
a)	handler = xattr_resolve_name(dentry->d_sb->s_xattr, &name)分发<br>
b)	handler->set(dentry, name, NULL, 0,XATTR_REPLACE, handler->flags)，ext4通过分发handler机制set函数分发到ext4_xattr_security_set<br>
	int credits = ext4_jbd2_credits_xattr(inode)<br>
	handle = ext4_journal_start(inode, EXT4_HT_XATTR, credits)<br>
iii.	<br>
	如果killpriv < 0，返回killpriv<br>
	如果error == 0 && killsuid == 1，调用error = __remove_suid(dentry, killsuid)擦除suid<br>
	如果error == 0，调用inode_has_no_xattr(inode)<br>
	返回error<br>
5.	<br>

	对inode->i_mutex解锁<br>
	如果ret > 0，调用err = generic_write_sync(file, pos, ret)<br>
	如果err < 0 && ret > 0<br>
ret = err;<br>
	调用blk_finish_plug(&plug)<br>
	return ret<br>
4.3.3.3.2.1.1	 ext4_unaligned_aio(inode, iov, nr_segs, pos)<br>
函数原型：static int ext4_unaligned_aio(struct inode *inode, const struct iovec *iov,unsigned long nr_segs, loff_t pos)<br>
参数： 文件inode节点，封装用户缓冲区的iovec结构，写入段数，写入文件位置<br>
数据对象：<br>
	inode节点，<br>
	文件系统超级块superblock<br>
功能： 判断写入位置pos或者写完之后的位置是否是块对齐的<br>
数据对象的变化：<br>
	如果写入位置大于文件大小i_size，返回0。获取文件大小时禁止内核抢占<br>
	判断(pos & blockmask) || (final_size & blockmask)是否为0，如果为0，说明是块对齐的，否则块未对齐<br>
4.3.3.3.2.1.2	ext4_unwritten_wait(inode)<br>
条件：如果块未对齐，进入该调用，进入之前需要加锁mutex_lock(ext4_aio_mutex(inode))<br>
函数原型： void ext4_unwritten_wait(struct inode *inode)<br>
参数：文件inode节点<br>
数据对象： 文件inode节点<br>
功能： 将inode加入ioend等待队列<br>
数据对象的变化：<br>
	调用ext4_ioend_wq(inode)<br>
4.3.3.3.2.2	generic_file_aio_write(iocb, iov, nr_segs, pos)<br>
4.3.3.4	fsnotify_modify(file)<br>
4.3.3.5	add_wchar(current, ret)<br>
4.3.3.6	inc_syscw(current)<br>
4.3.3.7	file_end_write(file)<br>
4.3.4	 file_pos_write<br>
4.3.5	 fdput<br>
