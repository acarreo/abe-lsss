sudo apt-get update
sudo apt-get install -y libgtest-dev libboost-all-dev

cd /usr/src/gtest
sudo cmake CMakeLists.txt
sudo make

sudo cp *.a /usr/local/lib
