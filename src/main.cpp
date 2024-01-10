#include "main.hpp"

int main(int argc, char *argv[])
{
    if (int retval = project::parse_opts(argc, argv); 0 != retval)
        return retval;

    if (int retval = project::init_prog(); 0 != retval)
        return retval;

    if (int retval = run_phase_one(project::prog); 0 != retval)
        return retval;

    if (!check_phase_one(project::prog))
        return -1;

    if (int retval = run_phase_two(project::prog); 0 != retval)
        return retval;

    return 0;
}
