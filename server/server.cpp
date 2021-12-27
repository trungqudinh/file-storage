#include <storage_server.hpp>

struct Arguments
{
    int port = 9002;
    std::string file_storing_path = "data/";
    std::string database_file = "database.db";

    bool parse(const int& argc, char **argv)
    {
        if (argc > 3)
        {
            port = atoi(argv[1]);
            file_storing_path = argv[2];
            database_file = argv[3];
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

    DatabaseIOStream::Instance().initialize(arguments.database_file);
    StorageServer server;
    server.storing_path = arguments.file_storing_path;
    server.run(arguments.port);

    return 0;
}
