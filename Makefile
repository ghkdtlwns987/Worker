worker : Run Compile Controller Config
	g++ -o  worker run.o compile.o controller.o config.o worker.h -std=c++11
Run : run.cpp
	g++ -std=c++11 -c run.cpp
Compile : compile.cpp
	g++ -std=c++11 -c compile.cpp
Controller : controller.cpp
	g++ -std=c++11 -c controller.cpp
Config : config.cpp
	g++ -std=c++11 -c config.cpp
clean :
	rm run.o compile.o controller.o config.o worker
