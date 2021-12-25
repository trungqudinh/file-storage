#pragma once
#include <checksum_handler.hpp>
#include <cstring>

std::string get_checksum_from_file(const std::string& file_path)
{
    char checksum[65];
    sha256_file(file_path.c_str(), checksum);
    return std::string(checksum);
}

std::string get_current_time()
{
    time_t rawtime;
    struct tm * timeinfo;
    char buffer[80];

    time (&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer,sizeof(buffer),"%d-%m-%Y_%H:%M:%S",timeinfo);
    return std::string(buffer);
}
