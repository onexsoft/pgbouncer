
/*
 * Safe and easy access to memory buffer.
 */

#include <usual/mbuf.h>

bool mbuf_make_room(struct MBuf *buf, unsigned len)
{
	unsigned new_alloc = buf->alloc_len;
	void *ptr;

	/* is it a dynamic buffer 判断是否是一个动态的空间*/
	if (buf->reader || buf->fixed)
		return false;

	/* maybe there is enough room already 判断是否有足够的空间*/
	if (buf->write_pos + len <= buf->alloc_len)
		return true;

	if (new_alloc == 0)//第一次分配128字节的数据
		new_alloc = 128;

	/* calc new alloc size */
	while (new_alloc < buf->write_pos + len)
		new_alloc *= 2;//如果新分配的空间小于要求的内存，则把内存空间扩大两倍

	/* realloc */
	ptr = realloc(buf->data, new_alloc);
	if (!ptr)
		return false;
	buf->data = ptr;
	buf->alloc_len = new_alloc;
	return true;
}

