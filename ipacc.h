//Header contains the main ipaccounter class to perform configuration file mapping and calculations stuff
//
#ifndef IP_ACCOUNTER_GUARD
#define IP_ACCOUTNER_GUARD

#include "ipaddr.h"
#include "memmap.h"

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <sstream>
#include <vector>
#include <string>
#include <deque>
#include <map>

#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

using std::endl;
using std::cout;
using std::cin;
using std::stringstream;
using std::string;
using std::ifstream;
using std::ofstream;
using std::deque;
using std::map;
using std::vector;

class ipaccounter {    
public:
    typedef long long int int64;
    enum date {week_day, month, day, curtime, year, all};
private:
    typedef struct { ipaddress net, mask; } network;
    inline void err_msg(const string &msg) const {cerr << msg << endl;}
    
    struct ip_info {
		ip_info(const string& ow = "", const int64& ins = 0, const int64& inr = 0, const int64& exs = 0, const int64& exr = 0) :
		owner(ow), in_s(ins), in_r(inr), ex_s(exs), ex_r(exr) {}
		string owner;
		int64 in_s, in_r, ex_s, ex_r, limit;

		inline bool limit_exceeded() const {return ex_s + ex_r > limit;}
	
		inline ip_info& operator +=(const ip_info& rhs) {
			in_s += rhs.in_s;
			in_r += rhs.in_r;
			ex_s += rhs.ex_s;
			ex_r += rhs.ex_r;
	    
			return *this;    
		}
		inline friend std::ostream& operator << (std::ostream& out, const ip_info& ii) {
			out << ii.ex_s << '\t' << ii.ex_r << '\t' << ii.in_s << '\t' << ii.in_r << endl;
			return out;
		}
    };
    typedef std::map<ipaddress, ip_info> ip_map;
    
    ip_map ips_;
    std::vector<network> internal_nets_;
    unsigned short dir_count_;
    std::string root_dir_, user_, time_stamp_;
    ipaddress router_port_; 
    
    bool is_internal_ip(const ipaddress& ip) const {
		size_t it = internal_nets_.size();
		while(it--) if(ip.belongs_to_net(internal_nets_[it].net, internal_nets_[it].mask)) return true;
		return false;
    }
    inline bool is_monitored_ip(const ipaddress& ip) const {return ips_.find(ip) != ips_.end();}
    void read_user_file(const char* path, std::deque<ipaddress>& IPs, std::deque<ip_info>& owners);

    inline void dump_cur_log(const string& path) {
		std::fstream cur(path.c_str(), std::ios::app|std::ios::out), curlog("curr.log");
		cur << time_stamp_ << endl;
		cur << curlog.rdbuf() << endl;
		cur.close();
		curlog.close();
    }
    void update_log(const string& path, bool sh_limit = false, const string& date = get_cur_date(all, false));

    void add_to_conf(const ipaddress& ip, const string& ow, const int64& limit);
    inline void compute(const size_t& bt, const ipaddress& from, const ipaddress& to) {
		if(is_monitored_ip(from))
			is_internal_ip(to) ? ips_[from].in_s += bt : ips_[from].ex_s += bt;
		if(is_monitored_ip(to))
		    is_internal_ip(from) ? ips_[to].in_r += bt : ips_[to].ex_r += bt;
    }
    void calc_traffic(const char* clog);
public:
    explicit ipaccounter(const char* filename = "ipacc.conf");
    inline void fetch_accounting() {
		//refresh the traffic log file
		string loginpart = string("rsh -l ") + user_ + string(" ") + router_port_.tostring();
		system("rm -f curr.log");
		system(string(loginpart + string(" terminal length 0")).c_str());
		system(string(loginpart + string(" clear ip accounting")).c_str());
		system(string(loginpart + string(" show ip accounting checkpoint >> curr.log")).c_str());
		system(string(loginpart + string(" clear ip accounting checkpoint")).c_str());
	
		calc_traffic("curr.log");
    }
    inline void update_logs() {	
		string path = root_dir_ + get_cur_date(year);
		path += '/';
		if(!dir_exists(root_dir_)) mkdir(root_dir_.c_str(), 0777);	
		if(!dir_exists(path)) mkdir(path.c_str(), 0777);
		update_log(path + string("peryear.log"));
	
		path += get_cur_date(month), path += '/';
		if(!dir_exists(path)) mkdir(path.c_str(), 0777);
		if(!dir_exists(path + string("daily/"))) mkdir((path + string("daily/")).c_str(), 0777);
		if(!dir_exists(path + string("logs/"))) mkdir((path + string("logs/")).c_str(), 0777);
	
		dump_cur_log(path + string("logs/") + get_cur_date(day) + string("dump.log"));
		update_log(path + string("permonth.log"), true);	
		update_log(path + string("daily/") + get_cur_date(day));
    }
    bool add_ip(const ipaddress& ip, const string& own, const ipaccounter::int64& limit, const string& dt_from, const string& dt_to, bool add = true);
    bool regenerate(const string& dt_from, const string& dt_to);
    void add_users_from_file(const char* path);

    static bool dir_exists(const string& path) {
		char buf[1024];
		bool ret;
		getcwd(&buf[0], 1024);
		int err = chdir(path.c_str());
		ret = err != -1 && errno != -2;
		chdir(&buf[0]);
		return ret;
    }
    static std::string get_cur_date(date dt = all, bool literal = true) {
        time_t rwtm;
		tm *tminf;
		time(&rwtm);
		tminf = localtime(&rwtm);
		std::string ret, it;
		if(literal) {
			ret = asctime(tminf);
			if(dt == all) return ret;
			stringstream sstream(ret);
			if(dt == week_day) sstream >> it;
			else if(dt == month) sstream >> it >> it;
			else if(dt == day) sstream >> it >> it >> it;
			else if(dt == curtime) sstream >> it >> it >> it >> it;
			else if(dt == year) sstream >> it >> it >> it >> it >> it;
			return it;
		}
		else {
			stringstream ss;
			ss << tminf->tm_year + 1900 << '-';
			tminf->tm_mon + 1 < 10 ? ss << '0', ss << tminf->tm_mon + 1 : ss << tminf->tm_mon + 1;
			ss << '-';
			tminf->tm_mday < 10 ? ss << '0', ss << tminf->tm_mday : ss << tminf->tm_mday;
 			return ss.str();
		}
    }
    static bool file_exists(const string& path) {
		FILE *file = fopen(path.c_str(), "r");
		bool yes = file != 0;
		if(yes) fclose(file);
		return yes;
    }
    static bool date_valid(const std::string& dat) {
		std::stringstream ss(dat);
		string time, day, month, year;
		ss >> day;
		if( !day.length() || day.length() > 2 || !isdigit(day[0]) || (day.length() == 2 && (!isdigit(day[1]) ||
			day[0] > '3' || (day[0] == '3' && day[1] > '1'))) || day[0] == '0') return false;
		ss >> month;
		if(!month.length() || (month != "Jan" &&  month != "Feb" &&  month != "Mar" &&
			month != "Apr" && month != "May" && month != "Jun" && month != "Jul" && month != "Aug" &&
			month != "Sep" && month != "Oct" && month != "Nov" && month != "Dec")) return false;								
		ss >> year;
		if(year.length() != 4 || !isdigit(year[0]) || !isdigit(year[1]) ||
			!isdigit(year[2]) || !isdigit(year[3]) || atoi(year.c_str()) < 2005) return false;
	    
			return true;
	}
};
#endif
