#include <client_endpoint.hpp>
#include <boost/optional.hpp>

using std::vector;
using std::string;

struct Arguments
{
    vector<string> file_paths;
    string uri;
    bool request_file_lists = false;

    bool parse(const int& argc, char **argv)
    {
        if (argc < 3)
        {
            std::cerr << "Invalid input" << std::endl;
            return false;
        }

        uri = argv[1];

        for(int i = 2; i < argc; i++)
        {
            if (strcmp(argv[i], "--files") == 0)
            {
                request_file_lists = true;
            }
            else if (argv[i][0] == '-')
            {
                std::cerr << "Unrecognize argument " << argv[i] << std::endl;
                return false;
            }
            else
            {
                file_paths.emplace_back(argv[i]);
            }
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

    for (auto const& file : arguments.file_paths)
    {
        if (!does_file_exist(file))
        {
            std::cerr << "File " << file << " does not exist" << std::endl;
            return 1;
        }
    }

    ClientEndpoint endpoint;
    int id = endpoint.connect(arguments.uri);

    // ================     Connect      ================
    if (-1 == id)
    {
        std::cerr << "Fail to connect to " << arguments.uri << std::endl;
        return 1;
    }
    std::cout << "> Created connection with uri " + arguments.uri + " id = " + std::to_string(id) << std::endl;
    ConnectionMetadata::ptr metadata = endpoint.get_metadata(id);
    while (metadata->get_status() != "Open")
    {
        wait_a_bit();
    }
    std::cout << *(endpoint.get_metadata(id)) << std::endl;

    // ================ Handle arguments ================
    if (arguments.request_file_lists)
    {
        endpoint.send_message(id, "FILES_LIST");
        endpoint.wait_for_respond(id);
    }

    endpoint.send_file(id, arguments.file_paths);
    return 0;
}
