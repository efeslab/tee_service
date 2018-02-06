# openssm
##General
Software Security Module, alternative to HSM (Hardware Security Module)

##Prequisites
The `Makefile` assumes GoogleTest framework is in '..'. 

To install:

```
cd ..
git clone https://github.com/google/googletest.git
cd googletest
cd googletest
autoreconf -fvi
g++ -isystem ./include -I. \
    -isystem ../googlemock/include -I../googlemock \
    -pthread -c ./src/gtest-all.cc
ar -rv libgtest.a gtest-all.o

cd ../googlemock
autoreconf -fvi
g++ -isystem ./include -I. \
    -isystem ../googletest/include -I../googletest \
    -pthread -c ./src/gmock-all.cc
ar -rv libgmock.a ../googletest/gtest-all.o gmock-all.o

cd ..
```

##Building and running tests
`make` will compile in real-hardware mode, and will run the c++ unit tests and the python end-to-end test/
'make SGX_MODE=SIM` will compile in simulation mode

To run the unit tests seperately run 
```
./RunTests
```

To run the end-to-end python tests: 
```
cd testing
python run_tests.py
```

##General structure
### OpenSSMServer class
The main class, managing the SSM.

###OpenSSMEnclave class
The enclave part of the SSM

###NetworkManager class
Helper class, used by OpenSSMServer to communicate on the network

###testing/run_tests.py
Running end-to-end tests, using Python UnitTest framework

###testing/run_tests.cpp
The main file running unit tests, implemented in GoogleTest framework and GoogleMock

##Contributing
This project is developed in a relaxed Test Driven Development method. I.e., for any high level functionality, first write the test, and then write the bare minimuim code to implement it (that's ideal, at least). Then, since you were  about to write code to test the SSM anyhow, add a end-toend test in run_tests.py .
