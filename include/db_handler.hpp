#include <boost/algorithm/string.hpp>

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>

using namespace std;

struct Record
{
    string user_id;
    string checksum;
    string request_id;
    string received_date;
    string file_name;
};

typedef vector<Record> Records;
typedef map<string, Records> UserBasedRecords;

class DatabaseIOStream
{
public:
    void initialize()
    {
        fout_.open(file_name, std::ios_base::app);
    }

    void insert(Records records)
    {
        for(const auto& rec : records)
        {
            fout_ << rec.user_id
                << " " << rec.checksum
                << " " << rec.request_id
                << " " << rec.received_date
                << " " << rec.file_name
                << " " << endl;
        }
    }

    void update(Records records)
    {
        //
    }

    UserBasedRecords select_all()
    {
        UserBasedRecords records;
        fin_.open(file_name);

        string line;
        while (std::getline(fin_, line))
        {
            Record record;
            std::istringstream iss(line);
            if (!(iss >> record.user_id
                        >> record.checksum
                        >> record.request_id
                        >> record.received_date
                        >> record.file_name))
            {
                cout << "Error on read data" << endl;
                break;
            }
            records[record.user_id].emplace_back(std::move(record));
        }
        fin_.close();
        return records;
    }

    ~DatabaseIOStream()
    {
        fout_.close();
    }
private:
    string file_name = "database.db";
    std::ofstream fout_;
    std::ifstream fin_;
};
