#pragma once
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <queue>
#include <pthread.h>
#include <thread>
#include <fcntl.h>
#include <dirent.h>
#include <wait.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/signal.h>
#include <stdarg.h>
#include <time.h>
#include<list>
#include<string>
using namespace std;

#define STD_MB 1048576
#define STD_F_LIM (STD_MB<<5)
#define STD_M_LIM (STD_MB<<7)
#define USER_ID_SIZE 16
#define BUFFER_SIZE 512

#define OJ_WT 1 		// Waiting
#define OJ_AC 2 		// Accept
#define OJ_WA 3 		// Wrong Answer
#define OJ_TL 4 		// Time Limit
#define OJ_ML 5 		// Memory Limit
#define OJ_CE 6 		// Compile Error
#define OJ_CO 7			// Compile OK
#define OJ_OL 8 		// Ouput Limit
#define OJ_RE 9 		// Runtime Error
#define OJ_PE 10 		// Presentation Error
#define OJ_ET 11		// Empty Test-data
#define OJ_JE 12		// Judging Error(Invalid Case)
#define OJ_SC 13		// System call Error

#define C_LANG 		1
#define CPP_LANG	2
#define JAVA 		3
#define PYTHON2 	4
#define PYTHON3 	5

#define REG_SYSCALL orig_rax
#define REG_RET rax
#define REG_ARG0 rdi
#define REG_ARG1 rsi

#define OKCALL -1;

class Config {
private:
	char work_dir[BUFFER_SIZE];
	char testcase_dir[BUFFER_SIZE];
	char java_xms[BUFFER_SIZE];
	char java_xmx[BUFFER_SIZE];
	char runtime_error_txt[BUFFER_SIZE];
	char compile_error_txt[BUFFER_SIZE];
	char result_out[BUFFER_SIZE];
	char total_user[BUFFER_SIZE];
	char user_dir[BUFFER_SIZE];
	char file_seperator[BUFFER_SIZE];
public:
	Config();
	char* get_work_dir();
	char* get_testcase_dir();
	char* get_java_xms();
	char* get_java_xmx();
	char* get_runtime_error_txt();
	char* get_compile_error_txt();
	char* get_result_out();
	char* get_total_user();
	char* get_user_dir();
	char* get_file_seperator();
	int after_equal(char * c);
	void trim(char * c);
	bool read_buf(char * buf, const char * key, char * value);
};

class Run {
private:
	int DEBUG;
	int language;
	int timeLimit;
	int memoryLimit;
	int number_of_testcase;
	list<string> *testcase_name;
	int max_topmemory;
	int max_usedtime;
	int final_judge_result;
	int testcase_judge_result;
	bool is_runtime_error_type(int testcase_judge_result);
	Config conf;
public:
	Run(int DEBUG, int language, int timeLimit, int memoryLimit,Config conf);
	int run();
	int exec_run(int DEBUG, int language, int timeLimit, int memoryLimit, string testcase_name);
	void run_program(int language, string testcase_name, int timeLimit, int memoryLimit);
	int watch_program(int pid, int language, string testcase_name, int memoryLimit, int &topmemory, int &usedtime);
	void custom_set_limit_run();
	void add_total_result(int final_judge_result, int max_usedtime, int max_topmemory);
	void add_testcase_result(string testcase_name, int testcase_judge_result);
	void renew_record(int testcase_judge_result, int topmemory, int usedtime);
	int get_proc_status(int pid, const char *mark);
	int get_page_fault_mem(struct rusage & ruse, pid_t & pidApp);
	long get_file_size(const char *filename);
	int execute_cmd(const char * fmt, ...);
	void print_runtimeerror(char * err);
	int isInFile(char *inFname);
	int make_in_file_name_list(list<string> *testcase_name);
	int child_process_exit(int pid, int status, int *result);
	int copy_file(string from_file, string to_file);
	void init_syscalls_limits(int language);
};

class Compile {
private:
	int DEBUG;
	int language;
	Config conf;
public:
	Compile(int DEBUG, int language,Config conf);
	int compile();
	int exec_compile(int language);
	void custom_set_limit_compile(int language);
	int copy_file(string from_file, string to_file);
	string compile_failed_result();
};

int main(int argc, char **argv);