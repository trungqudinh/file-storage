sudo apt-get install libssl-dev libboost-all-dev -y
sudo apt-get install devscripts build-essential lintian -y
git clone https://github.com/zaphoyd/websocketpp.git
make deb &&  sudo dpkg -i ../storage-server_1.0_amd64.deb
sudo dpkg -i ../storage-client_1.0_amd64.deb
