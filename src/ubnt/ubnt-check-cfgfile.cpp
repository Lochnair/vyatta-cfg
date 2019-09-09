#include <cparse/cparse.hpp>

using namespace cstore;

int
main(int argc, const char *argv[])
{
    if (argc < 2) {
        exit(1);
    }

    Cstore *cs = Cstore::createCstore(false);
    cnode::CfgNode *cn = cparse::parse_file(argv[1], *cs);

    exit((cn == NULL) ? 1 : 0);
}
