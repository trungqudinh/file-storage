#include <boost/algorithm/string.hpp>

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>

using namespace std;

static const string NULL_VALUE = "NULL";
struct Record
{
    string user_id = NULL_VALUE;
    string checksum = NULL_VALUE;
    string request_id = NULL_VALUE;
    string received_date = NULL_VALUE;
    string file_name = NULL_VALUE;
};

typedef vector<Record> Records;
typedef map<string, Records> UserBasedRecords;

class DatabaseIOStream
{
public:
    static DatabaseIOStream& Instance() {
        static DatabaseIOStream instance;
        return instance;
    }

    void initialize()
    {
        if (!is_open)
        {
            fout_.open(file_name, std::ios_base::app);
            is_open = true;
        }
    }

    void close()
    {
        if (is_open)
        {
            fout_.close();
            is_open = false;
        }
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
        close();
    }
    DatabaseIOStream(DatabaseIOStream const&) = delete;             // Copy construct
    DatabaseIOStream(DatabaseIOStream&&) = delete;                  // Move construct
    DatabaseIOStream& operator=(DatabaseIOStream const&) = delete;  // Copy assign
    DatabaseIOStream& operator=(DatabaseIOStream &&) = delete;      // Move assign
private:
    DatabaseIOStream()
    {
    }
    string file_name = "database.db";
    bool is_open = false;
    std::ofstream fout_;
    std::ifstream fin_;
};
