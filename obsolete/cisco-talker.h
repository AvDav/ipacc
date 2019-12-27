//this header contains a c++ wrapper to talk with cisco router's shell via telnet
#ifndef CISCO_TALKER_GUARD
#define CISCO_TALKER_GUARD

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <iostream>
#include <string>
#include <algorithm>

class cisco_talker {
    static const size_t buf_len = 1024;

    int sock;
    sockaddr_in addrin;
    std::string host;
    char data[buf_len];
    
    inline void cleanup(bool terminate = true) const {::shutdown(sock, 2); if(terminate) exit(1);}
    static inline void err_msg(const std::string& msg) {std::cout << msg << std::endl;}
    
public:
    explicit cisco_talker(const std::string& host_ = "212.42.193.16") : host(host_) {
		if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
			err_msg("Failed to create the socket!");
			cleanup();
		}
		addrin.sin_family = AF_INET;
		addrin.sin_port = htons(23);
		addrin.sin_addr.s_addr = ::inet_addr(host.c_str());
		if(::connect(sock, (sockaddr*)&addrin, sizeof(sockaddr)) < 0) {
			err_msg("Can not connect to the host");
			cleanup();
		}
    }
    virtual ~cisco_talker() {cleanup(false);}
    inline void put_cmd(std::string cmd) {
        cmd += "\n";
        if(::send(sock, cmd.c_str(), cmd.length(), 0) < 0) {
			err_msg(std::string("Failed to send ") + cmd + " command!");
			cleanup();
		}
    }
    void read_until(const char* pstr) {
        int cbret;
        while(0 < (cbret = ::recv(sock, &data[0], buf_len, 0))) {
			data[cbret] = '\0';
			if(strstr(&data[0], pstr)) break;
			::memset(&data[0], 0, buf_len);
        }
    }
    void get_row(std::string& str) {
        char ch;
        str.clear(), str.reserve(150);
        while(0 < ::recv(sock, &ch, 1, 0) && ch != '\r') str += ch;
        std::string::iterator old_end = str.end();
        str.erase(remove(str.begin(), str.end(), '\n'), old_end);
    }
    inline void miss_row() {std::string s; get_row(s);}
    inline void login(const char* password) {
        read_until(":"), put_cmd(password);
        read_until(">"), put_cmd("en");
        read_until(":"), put_cmd(password);
        read_until("#");
    }	
};
#endif