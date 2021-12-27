#pragma once
#include <iostream>
#include <string>
#include <boost/filesystem.hpp>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <utility.hpp>

using std::string;
using std::vector;

class StorageHandler
{
private:
    std::ofstream fout_;
public:
    string storing_path;
    std::ios_base::openmode mode = std::ios::out;
    pair<string, string> store(const string& file_name, vector<char> data, bool validate_existence = false)
    {
        string file_path = storing_path + file_name;
        if (validate_existence && exist(file_path))
        {
            std::cout << file_path << " already exists!" << std::endl;
        }
        else
        {
            std::cout << "Storing to " << file_path << std::endl;
            fout_.open(file_path, mode | std::ios::binary);
            fout_.write(data.data(), data.size());
            fout_.close();
        }
        return std::make_pair<string, string>(std::move(file_path), get_checksum_from_file(file_path));
    }

    bool exist(const string& file_name)
    {
        string file_path = storing_path + file_name;
        struct stat buffer;
        return (stat (file_path.c_str(), &buffer) == 0);
    }

    pair<bool, string> rename(const string& src, const string& dest)
    {
        std::string src_path = storing_path + src;
        std::string dest_path = storing_path + dest;

        if (!exist(src))
        {
            std::cerr << src << " does not exist!" << std::endl;
            return std::make_pair<bool, string>(false, std::move(src_path));
        }
        if (std::rename(src_path.c_str(), dest_path.c_str()))
        {
            std::perror("Error renaming");
            return std::make_pair<bool, string>(false, std::move(src_path));
        }
        return std::make_pair<bool, string>(true, std::move(dest_path));
    }
};
