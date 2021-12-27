#pragma once
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <checksum_handler.hpp>
#include <cstring>
#include <jsoncpp/json/json.h>

std::string generator_uuid()
{
    static boost::uuids::uuid uuid = boost::uuids::random_generator()();
    return boost::lexical_cast<std::string>(uuid);
}

void wait_a_bit()
{
     sleep(1);
}

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

    strftime(buffer,sizeof(buffer),"%Y-%m-%d_%H:%M:%S",timeinfo);
    return std::string(buffer);
}

template<typename CONTAINER>
Json::Value make_json_array(
        const CONTAINER& container,
        std::function<Json::Value(const typename CONTAINER::value_type&)> function
        ) {
    Json::Value array = Json::arrayValue;
    int i = 0;
    for (const auto& element : container) {
        array[i++] = function(element);
    }
    return array;
}

template<typename CONTAINER>
Json::Value make_json_array(const CONTAINER& container) {
    return make_json_array(container, [](const typename CONTAINER::value_type& value){return Json::Value(value);});
}

bool does_file_exist(const std::string& file_path )
{
    struct stat buffer;
    return (stat(file_path.c_str(), &buffer) == 0);
}
