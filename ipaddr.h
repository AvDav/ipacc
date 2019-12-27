//Header contains a wrapper for presenting the IP address abstraction
//it has all comparison operators (generally needed for sorting stuff).
#ifndef IP_ADDRESS_GUARD
#define IP_ADDRESS_GUARD

#include <arpa/inet.h>
#include <string>
#include <cassert>
#include <iostream>

class ipaddress {
	in_addr ip;
public:
    inline bool belongs_to_net(const ipaddress& net, const ipaddress& mask = ipaddress("255.255.255.0")) const {
		return (toulong() & mask.toulong()) == (net.toulong() & mask.toulong());
    }
    ipaddress(const std::string& doted = "127.0.0.1") {assert(inet_aton(doted.c_str(), &ip));}
    ipaddress(const unsigned long& IP) {ip.s_addr = htonl(IP);}
    inline unsigned long toulong() const {return ntohl(ip.s_addr);}
    inline std::string tostring() const {return std::string(inet_ntoa(ip));}
    inline bool operator>(const ipaddress& rhs) const {
		const unsigned char *This = (const unsigned char*)(&ip.s_addr), *That = (const unsigned char*)(&rhs.ip.s_addr);
		//ip as an integer is in network byte order (big-endian)
		if(This[0] > That[0]) return true;
		if(This[0] < That[0]) return false;
		if(This[1] > That[1]) return true;
		if(This[1] < That[1]) return false;
		if(This[2] > That[2]) return true;
		if(This[2] < That[2]) return false;
		if(This[3] > That[3]) return true;
		if(This[3] < That[3]) return false;
		return false;
    }
    inline bool operator<(const ipaddress& rhs) const {
		const unsigned char *This = (const unsigned char*)(&ip.s_addr), *That = (const unsigned char*)(&rhs.ip.s_addr);
		if(This[0] < That[0]) return true;
		if(This[0] > That[0]) return false;
		if(This[1] < That[1]) return true;
		if(This[1] > That[1]) return false;
		if(This[2] < That[2]) return true;
		if(This[2] > That[2]) return false;
		if(This[3] < That[3]) return true;
		if(This[3] > That[3]) return false;
		return false;
    }
    inline bool operator==(const ipaddress& rhs) const {return ip.s_addr == rhs.ip.s_addr;}
    inline bool operator!=(const ipaddress& rhs) const {return ip.s_addr != rhs.ip.s_addr;}
    inline bool operator>=(const ipaddress& rhs) const {return !((*this) < rhs);}
    inline bool operator<=(const ipaddress& rhs) const {return !((*this) > rhs);}
    ipaddress &operator=(const std::string& doted) {(*this) = ipaddress(doted); return *this;}
};
#endif
