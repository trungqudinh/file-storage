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
public:
    string storing_path;
    pair<string, string> store(const string& file_name, vector<char> data, bool validate_existence = false)
    {
        string file_path = storing_path + file_name;
        if (validate_existence && exist(file_name))
        {
            std::cout << file_path << " already exists!" << std::endl;
        }
        else
        {
            std::ofstream fout(file_path, std::ios::out | std::ios::binary);
            fout.write(data.data(), data.size());
            fout.close();
        }
        return std::make_pair<string, string>(std::move(file_path), get_checksum_from_file(file_path));
    }

    bool exist(const string& file_name)
    {
        string file_path = storing_path + file_name;
        struct stat buffer;
        return (stat (file_path.c_str(), &buffer) == 0);
    }
};
