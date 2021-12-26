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
    string file_size = NULL_VALUE;
};

typedef vector<Record> Records;
typedef map<string, Records> UserBasedRecords;
typedef map<string, map<string, map<string, Records> > > RecordsFilter;

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
            fout_.open(database_file_name, std::ios_base::app);
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

    void insert(const Records& records)
    {
        for(const auto& record : records)
        {
            fout_ << record.user_id
                << " " << record.checksum
                << " " << record.request_id
                << " " << record.received_date
                << " " << record.file_name
                << " " << record.file_size
                << endl;

            if (used_buffer_)
            {
                records[record.user_id][record.checksum][record.file_name].emplace_back(record);
            }
        }
    }

    void update(Records records)
    {
        //
    }

    RecordsFilter select_all()
    {
        RecordsFilter records;
        fin_.open(database_file_name);

        string line;
        while (std::getline(fin_, line))
        {
            Record record;
            std::istringstream iss(line);
            if (!(iss >> record.user_id
                        >> record.checksum
                        >> record.request_id
                        >> record.received_date
                        >> record.file_name
                        >> record.file_size))
            {
                cout << "Error on read data" << endl;
                break;
            }
            records[record.user_id][record.checksum][record.file_name].emplace_back(std::move(record));
        }
        fin_.close();
        return records;
    }

    RecordsFilter get_buffer() const {
        return buffer_;
    }

    void reload_buffer()
    {
        buffer_ = select_all();
        used_buffer_ = true;
    }

    ~DatabaseIOStream()
    {
        close();
    }

    DatabaseIOStream(DatabaseIOStream const&) = delete;
    DatabaseIOStream(DatabaseIOStream&&) = delete;
    DatabaseIOStream& operator=(DatabaseIOStream const&) = delete;
    DatabaseIOStream& operator=(DatabaseIOStream &&) = delete;
private:
    DatabaseIOStream() = default;
    string database_file_name = "database.db";
    bool is_open = false;
    bool used_buffer_ = false;
    RecordsFilter buffer_;
    std::ofstream fout_;
    std::ifstream fin_;
};
