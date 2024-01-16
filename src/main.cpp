#include "main.hpp"

int main(int argc, char *argv[])
{
    if (int retval = project::parse_opts(argc, argv); 0 != retval)
        return retval;

    project::prog_t prog;
    if (int retval = project::init_prog(prog); 0 != retval)
        return retval;

    for (int __ = 0; __ < 2; ++__)
    {
        project::client_t client;
        prog.active = &client;

        if (int retval = project::init_client(prog.loop, client, prog.settings); 0 != retval)
            return retval;

        if (int retval = run_phase_one(prog.loop, client); 0 != retval)
            return retval;

        if (!check_phase_one(prog, client))
            return -1;

        if (int retval = run_phase_two(prog.loop, client); 0 != retval)
            return retval;

        switch (client.composite.status)
        {
        case HTTP_STATUS_OK:
            return 0;
        case HTTP_STATUS_MOVED_PERMANENTLY:
        case HTTP_STATUS_FOUND:
        {
            project::opts.url = client.composite.headers["location"];
            std::cout << "Redirected to: " << project::opts.url << std::endl;
            break;
        }
        default:
            return -1;
        }
    }

    return 0;
}
