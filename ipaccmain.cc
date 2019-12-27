#include "ipacc.h"

int main(int argc, char* argv[]) {
    if(argc == 2 && ipaccounter::dir_exists(argv[1])) {
		chdir(argv[1]);
		ipaccounter accou;
		accou.fetch_accounting();
		accou.update_logs();
    }
    else {std::cout << "Usage:\n ipaccou [a current working directory]" << std::endl;}
    return EXIT_SUCCESS;
}