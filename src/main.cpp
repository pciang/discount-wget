#include "main.hpp"

int main(int argc, char *argv[])
{
    if (int retval = project::parse_opts(argc, argv); 0 != retval)
        return retval;

    project::prog_tpp prog;
    if (int retval = project::init_prog(prog); 0 != retval)
        return retval;

    if (int retval = run_phase_one(*prog); 0 != retval)
        return retval;

    if (!check_phase_one(*prog))
        return -1;

    if (int retval = run_phase_two(*prog); 0 != retval)
        return retval;

    return 0;
}
