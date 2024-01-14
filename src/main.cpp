#include "main.hpp"

int main(int argc, char *argv[])
{
    if (int retval = project::parse_opts(argc, argv); 0 != retval)
        return retval;

    project::prog_t prog;
    if (int retval = project::init_prog(prog); 0 != retval)
        return retval;

    if (int retval = project::init_client(prog.active, prog.settings); 0 != retval)
        return retval;

    if (int retval = run_phase_one(*prog.active); 0 != retval)
        return retval;

    if (!check_phase_one(*prog.active))
        return -1;

    if (int retval = run_phase_two(*prog.active); 0 != retval)
        return retval;

    return 0;
}
