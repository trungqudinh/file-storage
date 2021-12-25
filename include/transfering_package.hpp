#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/access.hpp>
#include <boost/serialization/vector.hpp>
#include <sstream>
#include <iostream>

using RawDataBuffer = std::string;

struct TransferingPackage
{
    std::string user_id;
    std::string request_id;
    std::string checksum;
    std::string file_name;
    std::vector<char> data;

    template<class Archive>
    void serialize(Archive & ar, const unsigned int)
    {
        ar & user_id;
        ar & request_id;
        ar & checksum;
        ar & file_name;
        ar & data;
    }

    static RawDataBuffer serialize(const TransferingPackage  &obj) {
        std::stringstream ss;
        boost::archive::binary_oarchive oa(ss);

        oa << obj;

        return ss.str();
    }

    static TransferingPackage deserialize(const RawDataBuffer &data) {
        std::stringstream ss(data);
        boost::archive::binary_iarchive ia(ss);

        TransferingPackage obj;
        ia >> obj;

        return obj;
    }
};
