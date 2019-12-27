#include "ipacc.h"

ipaccounter::ipaccounter(const char* filename) {
	std::ifstream file(filename);
	ipaddress ip;
	if(file.fail()) {err_msg(string("The configuration file ") + string(filename) + string(" doesn't exist!")); exit(1);}
	
	for(string line, item; std::getline(file, line); ) {
	    //skip comment lines
	    if(line.find('#') == string::npos) {
			std::stringstream sstream(line);
			sstream >> item;
	    
			if(item == "dir") {
				sstream >> item, root_dir_ = item;
				if(!(root_dir_.empty()) && root_dir_[root_dir_.length() - 1]!='/') root_dir_ += '/';
			}
			else if(item == "user") sstream >> user_;
			else if(item == "port")
    				sstream >> item, router_port_ = item;
			else if(item == "dir_count")
    				sstream >> dir_count_;
			else if(item == "ip") {
				sstream >> item;
				if(isdigit(item[0])) {
					ip = item;
					ips_[ip].owner = "unknown";
					sstream >> ips_[ip].limit;
				}
				else {
					string s;
					sstream >> s;
					ip = s;
					ips_[ip].owner = item;
					sstream >> ips_[ip].limit;
				}
			}
			else if(item == "net") {
				network nw;
				sstream >> item;
				nw.net = item;
				sstream >> item;
				nw.mask = item.length() ? item : "255.255.255.0";
				internal_nets_.push_back(nw);
			}
	    }
	}
}

void ipaccounter::read_user_file(const char* path, std::deque<ipaddress>& IPs, std::deque<ip_info>& owners) {
	if(file_exists(path)) {
	    string IP;
	    ip_info inf;
	    stringstream ss;
	    ifstream u_file(path);
	    
	    //read new users
	    if(u_file.fail()) {
	        err_msg(string("An error occurred while opening the ") + string(path) + string(" file!"));
	        exit(1);
	    }
	    for(string line; std::getline(u_file, line); ) {
			inf.limit = -1;
	        ss.clear();
	        ss.str(line);
	        ss >> inf.owner >> IP >> inf.limit;
		
	        //skip comments
			if(user_.find('#') != string::npos) continue;
			if(inf.limit < 0) inf.limit = 524288000; //500 Mb by default
			owners.push_back(inf);
			IPs.push_back(ipaddress(IP));
	    }
	    u_file.close();
	}
}

void ipaccounter::update_log(const string& path, bool sh_limit, const string& date) {
	string s;
	int64 num;
	ip_info inf;
	ipaddress ip;
	ip_map tmp = ips_;
	if(file_exists(path)) {
	    ifstream logf(path.c_str());
	    if(logf.fail()) err_msg(string("Can not open ") + path + string(" file!")), exit(1);
	    
	    for(string line; std::getline(logf, line); ) {
			if(line.find('#') != string::npos) continue;
			stringstream ss(line);
			//ip address or date?
			ss >> s;		
			//skip date
			if(s.find_first_of("/-") != string::npos) 
				ss >> s;
			ip = s;
			if(is_monitored_ip(ip)) {
				//skip owner
				ss >> s;
				ss >> num, tmp[ip].ex_s += num;
				ss >> num, tmp[ip].ex_r += num;
				ss >> num, tmp[ip].in_s += num;
				ss >> num, tmp[ip].in_r += num;
			}
	    }
	}
	ofstream logf(path.c_str());
	if(logf.fail()) err_msg(string("Can not open ") + path + " file!"), exit(1);
	for(ip_map::const_iterator i = tmp.begin(), last = tmp.end(); i != last; ++i)
	    if(is_monitored_ip(i->first)) {
			inf = i->second;
			logf << date << '\t';
			logf << i->first.tostring() << '\t' << inf.owner << '\t' << inf.ex_s << '\t' << inf.ex_r << '\t';
			logf << inf.in_s << '\t' << inf.in_r;
			if(sh_limit) logf << '\t' << inf.limit - inf.ex_s - inf.ex_r; 
			logf << endl;
	    }
}

void ipaccounter::add_to_conf(const ipaddress& ip, const string& ow, const int64& limit) {
	ifstream conf("ipacc.conf");
	if(conf.fail()) {err_msg("An error occurred while reading ipacc.conf!"); exit(1);}
	std::vector<string> lines;
	string it;
	int last_idx = 0, i = 0;
	for(string ln; std::getline(conf, ln); ++i) {
	    stringstream ss(ln);
	    ss >> it;
	    if(it == "ip") last_idx = i;
	    lines.push_back(ln);
	}
	stringstream ss;
	ss << limit;
	it = string("ip ") + ow + string(" ") + ip.tostring() + string(" ") + ss.str();
	lines.insert(lines.begin() + last_idx, it);
	conf.close();
	ofstream updateconf("ipacc.conf");
	if(updateconf.fail()) {err_msg("An error occurred while writing to ipacc.conf!"); exit(1);}
	for(int i = 0, n = lines.size(); i < n; updateconf << lines[i++] << endl);
}

void ipaccounter::calc_traffic(const char* clog) {
	mem_map mem(clog);
	if(mem) {
	    string s;
	    vector<string> strs;
	    ipaddress src1, dst1, src2, dst2;
	    size_t bytes1, bytes2, pack1, pack2;
	    char* data = mem.data();
	    
	    strs.reserve(mem.length()/60);
	    s.reserve(60);
	    
	    for(size_t i = 0, len = mem.length(); i < len; ++i) {
			if((data[i] == '\r' || data[i] == '\n'))  {
				if(8 < s.length() && s.find("Source") == string::npos && s.find("Accounting") == string::npos)
					strs.push_back(s); 
				s = "";
			}
			else s += data[i];
	    }
	    vector<bool> process_row(strs.size(), false);
	    for(vector<string>::iterator i = strs.begin(), last = strs.end(); i != last; ++i) {
		//already processed - skip
			if(process_row[i - strs.begin()]) continue;
		
			stringstream ss(*i);						  
			ss >> s;
			src1 = s;
			ss >> s;
			dst1 = s;
	    				
			ss >> pack1;
    		ss >> bytes1;
		
			if(is_monitored_ip(src1) || is_monitored_ip(dst1)) {
				//look in next dir_count_ items for response
				for(vector<string>::iterator ii = i + 1, llast = i + dir_count_; ii <= llast && ii != last; ++ii) {
					ss.clear();
					ss.str(*ii);
					ss >> s;
					src2 = s;
					ss >> s;
					dst2 = s;
					ss >> pack2;
					ss >> bytes2;
					if(src1 == dst2 && src2 == dst1) {
						compute(bytes1, src1, dst1);
						compute(bytes2, src2, dst2);
						process_row[i - strs.begin()] = process_row[ii - strs.begin()] = true;
						break;	
					}
				}
			}
	    }
	}
}

bool ipaccounter::add_ip(const ipaddress& ip, const string& own, const ipaccounter::int64& limit, const string& dt_from, const string& dt_to, bool add) {
	if(is_monitored_ip(ip) || limit <= 0) return false;
	
	string time_from, month_from, time_to, month_to, logdate, src, dst, file1, file2, date;
	short day_to, day_from, year_to, year_from;
	int64 bytes;
	
	stringstream ss(dt_from);
	ss >> day_from >> month_from >> year_from;
	
	ss.clear();
	ss.str(dt_to);
	ss >> day_to >> month_to >> year_to;
	ss.clear();
	ss.str("");
	
	static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sept", "Oct", "Nov", "Dec"};
	short start_m, end_m;
	for(int i = 0; i < 12; ++i) {if(month_from == months[i]) start_m = i; if(month_to == months[i]) end_m = i;}
	
	for(short mn, dy, yr = year_from; yr <= year_to; ++yr) {
	    ss << yr;
	    string path = root_dir_ + ss.str();
	    path += '/';
	    ss.clear();
	    ss.str("");
	    
	    if(!dir_exists(path)) continue;
	    
	    ip_info yearly;
	    yearly.owner = own;
	    yearly.limit = limit;
	    
	    int st = yr != year_from ? 0 : start_m, en = yr != year_to ? 11 : end_m;

	    for(mn = st; mn <= en; ++mn) {
			string ppath = path;
			ppath += months[mn];
			ppath += '/';
		
			if(!dir_exists(ppath)) continue;
		
			ip_info monthly;
			monthly.owner = own;
			monthly.limit = limit;
		
			int ds = mn != st ? 1 : day_from, de = mn != en ? 31 : day_to;
		
			for(dy = ds; dy <= de; ++dy) {
				ss.clear();
				ss.str("");
				ss << dy;
				string dailyname = ppath + string("daily/") + ss.str();
				string logname = ppath + string("logs/") + ss.str() + string("dump.log");
		    
				if(!file_exists(dailyname) || !file_exists(logname)) continue;		    
		    
				ifstream logf(logname.c_str()), dailf(dailyname.c_str());
				if(!dailf.fail() && !logf.fail()) {
					bool do_cont = false;
					for(string ln; std::getline(dailf, ln); ) {
						string ipstr;
						ss.clear();
						ss.str(ln);
						ss >> ipstr;
			    
						//if date
						if(ipstr.find_first_of("-/") != string::npos)
						ss >> ipstr;
						if(ipstr == ip.tostring()) {do_cont = true; break;}
					}
					//ip is already in daily log then skip
					if(do_cont) continue;
			
					ip_info daily;
					daily.owner = own;
					daily.limit = limit;
			
					system("clear");
					cout << "Adding " << own << " user with " << ip.tostring() << " IP, please wait..." << endl;
					cout << "Processing " << logname << endl;
			
					for(string ln; std::getline(logf, ln); ) {
						//skip blah stuff
						if(ln.find("Source") != string::npos || ln.find("Accounting") != string::npos) continue;
						//if date
						if(ln.length() == 8 && isdigit(ln[0])) {logdate = ln; continue;}
			    
						ss.clear();
						ss.str(ln);
						ss >> src;
						ss >> dst;
			    
						//packet count
						ss >> bytes;
						if(bytes == 1) continue;
						//bytes Rx/Tx
						ss >> bytes;
			    
						if(src == ip.tostring()) 
							is_internal_ip(ipaddress(dst)) ? daily.in_s += bytes : daily.ex_s += bytes;
						if(dst == ip.tostring())
							is_internal_ip(ipaddress(src)) ? daily.in_r += bytes : daily.ex_r += bytes;
					}
			
					monthly += daily;
					ips_[ip] = daily;
			
					ss.clear();
					ss.str("");
					ss << yr << '-';
					mn + 1 < 10 ? ss << '0' << mn + 1 : ss << mn + 1;
					ss << '-';
					dy < 10 ? ss << '0' << dy : ss << dy;
					date = ss.str();
			
					update_log(dailyname, false, date);
					ips_.erase(ip);
				}
			}
			yearly += monthly;
			ips_[ip] = monthly;
			update_log(ppath + string("permonth.log"), true, date);
			ips_.erase(ip);
	    }
	    ips_[ip] = yearly;
	    update_log(path + string("peryear.log"), false, date);
	    ips_.erase(ip);
	}
	if(add) add_to_conf(ip, own, limit);
}

bool ipaccounter::regenerate(const string& dt_from, const string& dt_to) {
	string month_from,  month_to, date;
	short day_to, day_from, year_to, year_from;
	
	stringstream ss1(dt_from), ss2(dt_to);
	ss1 >> day_from >> month_from >> year_from;
	ss2 >> day_to >> month_to >> year_to;
	static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sept", "Oct", "Nov", "Dec"};
	short start_m, end_m;
	
	for(int i = 0; i < 12; ++i) {
		if(month_from == months[i]) 
			start_m = i; 
		if(month_to == months[i]) 
			end_m = i;
	}
	
	for(short mn, dy, yr = year_from; yr <= year_to; ++yr) {
	    stringstream ss;
	    ss << yr;
	    string path = root_dir_ + ss.str();
	    path += '/';
	    if(!dir_exists(path)) continue;
	    int st = yr != year_from ? 0 : start_m, en = yr != year_to ? 11 : end_m;
	    for(mn = st; mn <= en; ++mn) {
			string ppath = path;
			ppath += months[mn];
			ppath += '/';
		
			if(!dir_exists(ppath)) continue;
			int ds = mn != st ? 1 : day_from, de = mn != en ? 31 : day_to;
		
			for(dy = ds; dy <= de; ++dy) {
				stringstream ss;
				ss << dy;
				string dailyname = ppath + string("daily/") + ss.str();
				string logname = ppath + string("logs/") + ss.str() + string("dump.log");
		    
				if(!file_exists(dailyname)) continue;
		    
				ss.str("");
				ss << yr << '-';
				mn + 1 < 10 ? ss << '0' << mn + 1 : ss << mn + 1;
				ss << '-';
				dy < 10 ? ss << '0' << dy : ss << dy; 
				date = ss.str();
				update_log(dailyname, false, date);
			}
			update_log(ppath + string("permonth.log"), true, date);
	    }
	    update_log(path + string("peryear.log"), false, date);
	}
}

void ipaccounter::add_users_from_file(const char* path) {
	if(file_exists(path)) {
	    stringstream ss;
	    const string dt_from = "1 Mar 2005";
	    int64 limit = -1;
	    string dt_to = get_cur_date(day), user, IP, cmd;
	    dt_to += ' ', dt_to += get_cur_date(month), dt_to += ' ', dt_to += get_cur_date(year);
	    std::deque<string> owners;
	    std::deque<ipaddress> IPs;
	    
	    ifstream u_file(path);
	    if(u_file.fail()) {
			err_msg(string("An error occurred while opening the ") + string(path) + string(" file!")); 
			exit(1);
	    }
	    for(string line; std::getline(u_file, line); )	{
			ss.clear();
			ss.str(line);
			ss >> user >> IP >> limit;
		
			//skip  comment
			if(user.find('#') != string::npos) continue;
		
			if(limit < 0) limit = 524288000; //500 Mb by default
			owners.push_back(user);
			IPs.push_back(ipaddress(IP));
	    }
	    u_file.close();
	    
	    //check for duplicates
	    int n = IPs.size();
	    for(int j, i = 0; i < n; ++i)
	    	for(j = i + 1; j < n; ++j)
				if(IPs[i] == IPs[j]) {
					cout << owners[i] << " and " << owners[j] << " have the same " << IPs[i].tostring() \
						 << " address, the program will terminate." << endl;
					exit(1);
				}
	    //calculate traffic for each user
	    ss.clear();
	    ss.str("");
	    ss << limit;

	    for(int i = 0; i < n; ++i) {
			string cmd = "./addip ";
			cmd += IPs[i].tostring(), cmd += " ";
			cmd += owners[i], cmd += " ";
			cmd += ss.str(), cmd += " ";
			cmd += dt_from, cmd += " ";
			cmd += dt_to;
			system(cmd.c_str());
	    }
	}
}