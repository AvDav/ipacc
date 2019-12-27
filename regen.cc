#include "ipacc.h"

int main() {
    bool invalid = true;
    string date_from, date_to;
    do {
        cout << "Change file format from/to date: [e.g. 1 Mar 2005/1 Apr 2005]: ";
        std::getline(cin, date_from, '/');
        std::getline(cin, date_to, '\n');
        if((invalid = !ipaccounter::date_valid(date_from) || !ipaccounter::date_valid(date_to))) cout << "Invalid date(s)!" << endl;
    }
    while(invalid);
    ipaccounter().regenerate(date_from, date_to);				
    return EXIT_SUCCESS;
}