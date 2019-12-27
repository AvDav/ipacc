#include "ipacc.h"
#include <cstdlib>
#include <cassert>

int main(int argc, char* argv[]) {
    ipaccounter accou;
    cout << argc << endl;
    if(argc == 2) {
		if(ipaccounter::file_exists(argv[1])) accou.add_users_from_file(argv[1]); 
		else { cout << "No such file." << endl; exit(1); }
    }	
    else {
		char c;
		bool invalid = true;
    	ipaccounter::int64 limit;
    	string ipstr, owner, date_from, date_to;
		stringstream ss;
    
		if(argc == 10) {
			ipstr = argv[1];
			owner = argv[2];
			ss.clear();
			ss.str(argv[3]);
			ss >> limit;
			date_from += argv[4], date_from += ' ';
			date_from += argv[5], date_from += ' ';
			date_from += argv[6];
			
			date_to += argv[7], date_to += ' ';	    
			date_to += argv[8], date_to += ' ';
			date_to += argv[9];
			if(isdigit(owner[0]) || !ipaccounter::date_valid(date_from) || !ipaccounter::date_valid(date_to))
			{ cout << "Invalid date(s) or owner (first char should not be a digit!)." << endl; exit(1); }
		}
		else {
			//input user info
			cout << "new ip address: ";
			cin >> ipstr;
		
			do {
				cout << "owner (any word except 'include' with non-digit first char): ";
				cin >> owner;
			}
			while(isdigit(owner[0]) || owner == "include");
		
			cout << "limit of traffic in bytes: ";
			cin >> limit;
		
			do {
				cout << "Collect accounting starting from/to date: [e.g. 1 Mar 2005/1 Apr 2005]: ";
				std::getline(cin, date_from, '/');
				std::getline(cin, date_to, '\n');
				if((invalid = !ipaccounter::date_valid(date_from) || !ipaccounter::date_valid(date_to))) {cout << "Invalid date(s)!" << endl;}
			}
			while(invalid);
		}
		accou.add_ip(ipaddress(ipstr), owner, limit, date_from, date_to);
    }
    return 0;
}