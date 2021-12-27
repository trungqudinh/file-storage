#include <storage_server.hpp>

struct Arguments
{
    int port = 9002;

    bool parse(const int& argc, char **argv)
    {
        if (argc > 1)
        {
            port = atoi(argv[1]);
        }

        return true;
    }
};


int main(int argc, char **argv)
{
    Arguments arguments;
    if (!arguments.parse(argc, argv))
    {
        return 1;
    };

    StorageServer server;
    server.run(arguments.port);

    return 0;
}
