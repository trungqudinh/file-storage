## Quick tour

We can run the `./install.sh` script to start from building to deploying steps

Here the short content in `./install.sh`

```
sudo apt-get install libssl-dev libboost-all-dev -y
sudo apt-get install devscripts build-essential lintian dh-make -y
git clone https://github.com/zaphoyd/websocketpp.git
make deb &&  sudo dpkg -i ../storage-server_1.0_amd64.deb
sudo dpkg -i ../storage-client_1.0_amd64.deb
```

## Building source code

- First, we need to clone the Websocket++ library repository to this top repo
```
git clone https://github.com/trungqudinh/file-storage.git
cd file-storage
git clone https://github.com/zaphoyd/websocketpp.git
```

- Because of this based on Websocket++ library, so we need some other libraries to build source code
```
sudo apt-get install libssl-dev libboost-all-dev libjsoncpp-dev -y
``` 

- Then run with make command.
```
make client # to build client
make server # to build server
make all    # to build both
```

- The binary file can be found in `/build` directory after built.
```
build/
├── client
└── server
```

## Run the app

### Server

- Create the *data/* directory with same level of the binary file. Anh not to place an SSL Keychain file in the place to call the command.

To run the server we use:

  > ./build/server <PORT> <FILE_STORING_PATH> <DATABASE_FILE_NAME>
 
Example:
```
./build/server 9002 data/ database.db
```

Default value of abave parameter is:
```
              PORT: 9002
 FILE_STORING_PATH: data/
DATABASE_FILE_NAME: database.db
```

**NOTE**: `FILE_STORING_PATH` need to have a trailing "/" charater.

### Client

Use the command to run the client code:
  > ./build/client URI [OPTIONS] [FILES_TO_SEND]
  
```
OPTIONS:
    --files:        return the file infomation that user_id has sent before.
                    The contain of file is JSON array with this format:
                    {
                        files : [
                            [
                                file_name,
                                file_size,
                                file_check_sum,
                            ],
                            ...
                        ]
                    }
    FILES_TO_SEND   The list of files, or single file to send to server.
```
Example:
```
./build/client wss://localhost:9002/client/ws?content-type=audio/x-raw,user_id=123456789 --files
./build/client wss://localhost:9002/client/ws?content-type=audio/x-raw,user_id=testuser1 --files test/test_data1.txt
./build/client wss://localhost:9002/client/ws?content-type=audio/x-raw,user_id=account01 --files test/test_data1.txt /usr/bin/ls
```

Example output of `--files` option:

    {
        "files" : [
            [
                "tree",
                "85608",
                "75a256ed8adae3bdf57e433f97971ed6cdf7cabe5a3d0de9bfd44b3658b2fa5c"
            ],
            [
                "output.dat",
                "25165824",
                "95aeaae03b56c171cf88753c821630a3c24f1fcf406cec3e17d56781aa3f8369"
            ]
        ]
    }

## Build debian package

We can build debian package for fast installation and easier to install on other machine
```
make deb 
sudo dpkg -i ../storage-server_1.0_amd64.deb
sudo dpkg -i ../storage-client_1.0_amd64.deb
```


## How does they work?

### On client side

Every time run command, client can send data file to server and store there.
If the data to large it will be split by smaller chunks. Each chunk will have
max size is 10 * 1024 * 1024 bytes. And they're hard code currently.

```
  +---------+  +--------+         +---------+  +--------+
  |         |  |        |         |         |  |        |
  | Chunk 1 |  |Chunk 2 |   ...   | Chunk   |  |Chunk n |
  |         |  |        |         |   n-1   |  | x bytes|
  +---------+  +--------+         +---------+  +--------+
```

### On server side

Server will received chunk from clients, then merge them on server side. Files are stored with the name is is checksum value.
For that, we can prevent to received same file.
The database are a normal text file that store:

- user_id: Id of user
- file_checksum: Checksum value of file.
- request_id
- received_time
- file_name: If different user_id sent same file with different name. They stil be saved. But there's only one file are save.
- file_size

Some record in database
```
123456789 028bb3b3b88f501ae7ba6f53b828ca0555e2561ac413f2f8b04d09d1248f360c 70da434d-40a1-4b89-ad9b-7ac9f62dc8d0 2021-12-28_04:35:23 server.pem 3505
123456789 1e39354a6e481dac48375bfebb126fd96aed4e23bab3c53ed6ecf1c5e4d5736d d4b6f114-dec6-46ce-af51-50fdc53b6e01 2021-12-28_04:37:07 ls 142144
usertest1 75a256ed8adae3bdf57e433f97971ed6cdf7cabe5a3d0de9bfd44b3658b2fa5c 6ec3cd6a-ec3a-4907-b7c4-1878d0fdf4d5 2021-12-28_04:39:39 tree 85608
usertest1 95aeaae03b56c171cf88753c821630a3c24f1fcf406cec3e17d56781aa3f8369 53c63d94-7d93-44e2-8df0-01b092656656 2021-12-28_04:40:27 output.dat 25165824
usertest1 95aeaae03b56c171cf88753c821630a3c24f1fcf406cec3e17d56781aa3f8369 c0af94b0-bff6-48e5-b8f9-707f1342c2cd 2021-12-28_04:41:43 output.dat 25165824
```

### Inside a chunk

Each chunk file will contain some following value:

- curr_checksum: The current checksum of current sending chunk.
- prev_checksum: With the chunk n, this is checksum value of chunk n-1
- file_name
- file_checksum: The checksum of full file. Based on the, server know when the file are finished.
- data: The bytes data of the chunk.

With each received chunk, server will send back the `prev_checksum` to client to notify that server's ready to receive the next one.
