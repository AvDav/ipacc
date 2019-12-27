#ifndef MEM_MAP_GUARD
#define MEM_MAP_GUARD

#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdexcept>

class mem_map {
protected:
    int fd;
    size_t len;
    char *dat;
    bool valid;
    
    void cleanup() { close(fd); ::munmap(dat, len); }
public:
    mem_map(const char *pth, void *start = 0, int prot = PROT_READ | PROT_WRITE, 
	    int flags = MAP_SHARED,  off_t offset = 0, int oflags = O_RDWR) : valid(true) {
		struct stat st;
		if((fd = ::open(pth, oflags)) < 0 || fstat(fd, &st) < 0) valid = false;
		else {
			len = st.st_size;
			if((dat = (char*)::mmap(start, len, prot, flags, fd, offset)) == (void*)-1) valid = false;    
		}
    }   
    inline operator bool() const {return valid;}
    inline char* data() {return dat;}
    char& operator [](const size_t &i)	throw(std::out_of_range) {
		if(i >= len) throw std::out_of_range("invalid index");
		return dat[i];
    }
    const char &operator [](const size_t &i) const throw(std::out_of_range) {
		if(i >= len) throw std::out_of_range("invalid index");
		return dat[i];
    }
    inline size_t length() const { return len; }
    virtual ~mem_map() {cleanup();}
};

#endif