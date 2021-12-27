#include <client_endpoint.hpp>

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        std::cerr << "Invalid input" << std::endl;
        return 1;
    }
    std::string uri = argv[1];
    std::vector<std::string> file_paths;

    bool request_files_list = 0;

    for(int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "--files") == 0)
        {
            request_files_list = true;
        }
        else
        {
            file_paths.emplace_back(argv[i]);
        }
    }

    ClientEndpoint endpoint;
    int id = endpoint.connect(uri);
    if (-1 == id)
    {
        std::cerr << "Fail to connect to " << uri << std::endl;
        return 1;
    }
    std::cout << "> Created connection with uri " + uri + " id = " + std::to_string(id) << std::endl;
    ConnectionMetadata::ptr metadata = endpoint.get_metadata(id);
    while (metadata->get_status() != "Open")
    {
        wait_a_bit();
    }
    std::cout << *(endpoint.get_metadata(id)) << std::endl;
    if (request_files_list)
    {
        endpoint.send_message(id, "FILES_LIST");
        endpoint.wait_for_respond(id);
    }
    endpoint.send_file(id, file_paths);
    return 0;
}
