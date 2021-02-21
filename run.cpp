#include "worker.h"

const int call_array_size = 512;
int call_counter[10][call_array_size] = { 0 };

Run::Run(int DEBUG, int language, int timeLimit, int memoryLimit, Config conf) {
	this->DEBUG = DEBUG;
	this->language = language;
	this->timeLimit = timeLimit;
	this->memoryLimit = memoryLimit;
	this->number_of_testcase;
	this->conf = conf;
	max_topmemory = 0;
	max_usedtime = 0;
	final_judge_result = OJ_AC;
	testcase_judge_result = OJ_AC;
}

int Run::run() {
	list<string> testcase_name;

	if (DEBUG)
		printf("[DEBUG][Run start]\n");

	init_syscalls_limits(this->language);

	chdir(conf.get_work_dir());

	make_in_file_name_list(&testcase_name);//testcase의 이름을 testcase_name 리스트에 저장한다.

	list<string>::iterator iter;

	for (iter = testcase_name.begin(); iter != testcase_name.end(); ++iter) {//모든 테스트 케이스 실행
		exec_run(DEBUG, language, timeLimit, memoryLimit, *iter);
	}

	add_total_result(final_judge_result, max_usedtime, max_topmemory);

	if (DEBUG)
		printf("[DEBUG][Run finish]\n");//로그로 남길 것
}

int Run::exec_run(int DEBUG, int language, int timeLimit, int memoryLimit, string testcase_name) {
	int topmemory = 0;
	int usedtime = 0;
	pid_t pid;
	pid = fork();
	if (pid == 0) { // Child process
		run_program(language, testcase_name, timeLimit / 1000, memoryLimit);

		if (DEBUG)
			printf("[ERROR][Runtime Error] : run_program failed\n");
		exit(1);
	}
	else { // Parent process
		testcase_judge_result =
			watch_program(pid, language, testcase_name, memoryLimit, topmemory, usedtime);
		// Child process 감시
	}

	add_testcase_result(testcase_name, testcase_judge_result);

	renew_record(testcase_judge_result, topmemory, usedtime);//final, max 값 갱신
}

void Run::run_program(int language, string testcase_name, int timeLimit, int memoryLimit) {

	string input_file_path = conf.get_testcase_dir();
	input_file_path = input_file_path.append("/").append(testcase_name).append(".in");

	if (DEBUG)
		printf("[Info][run_program() start]\n");

	freopen(input_file_path.c_str(), "r", stdin);		// input
	freopen(conf.get_result_out(), "w", stdout);	// output
	freopen(conf.get_runtime_error_txt(), "w", stderr); //error

	ptrace(PTRACE_TRACEME, 0, NULL, NULL); // process trace, 부모에 의해 추적됨

	while (setgid(1000) != 0) sleep(1);
	while (setuid(1000) != 0) sleep(1);
	while (setresuid(1000, 1000, 1000) != 0) sleep(1);

	custom_set_limit_run();

	switch (language) {
	case C_LANG:
	case CPP_LANG:
		execl("./Main", "./Main", NULL);
		break;
	case JAVA:
		execl("/usr/bin/java", "/usr/bin/java", conf.get_java_xms(), conf.get_java_xmx(), "-Djava.security.manager", "-Djava.security.policy=./java.policy", "Main", NULL);
		break;
	case PYTHON2:
		execl("/usr/bin/python2", "/usr/bin/python2", "Main.py", NULL);
		break;
	case PYTHON3:
		execlp("python3", "python3", "Main.py", NULL);
		break;
	}//실행 파일 찾기 실패 시, /usr/bin의 실행 파일로 직접 실행해 볼 것

	printf("[ERROR][Runtime error] : execl() failed\n");

	if (DEBUG)
		perror("[ERROR][Runtime error] : execl() failed\n");

	exit(0);

}

int Run::watch_program(int pid, int language, string testcase_name, int memoryLimit, int &topmemory, int &usedtime) {
	int status, tempmemory, exitcode;
	struct rusage rus;
	string testcase_infile_path = conf.get_testcase_dir();
	testcase_infile_path.append("/").append(testcase_name).append(".in");// -> testcase/'testcase_name'.in
	string testcase_outfile_path = conf.get_testcase_dir();
	testcase_outfile_path.append("/").append(testcase_name).append(".out");// -> testcase/'testcase_name'.out
	int result = OJ_AC;
	bool exeCodeFlag = true;
	struct user_regs_struct reg;

	if (DEBUG)
		printf("[DEBUG][watch_program() start]\n");


	if (topmemory == 0)
		topmemory = get_proc_status(pid, "VmRss:") << 10;		//get allocated real physical memory size, KB -> B

	while (1) {
		wait4(pid, &status, 0, &rus);
		/////////////////////////////////////////////////////////////////////////////////
		//child process off

		if (exeCodeFlag) {//첫 실행 시
			exeCodeFlag = false;
			ptrace(PTRACE_SYSCALL, pid, NULL, NULL);//restart child proc
			continue;
		}

		// gets the size of the memory used by the process
		if (language == JAVA)
			tempmemory = get_page_fault_mem(rus, pid);
		else
			tempmemory = get_proc_status(pid, "VmPeak:") << 10;

		if (tempmemory > topmemory)
			topmemory = tempmemory;

		//check memeory limit(OJ_ML)
		if (topmemory > memoryLimit * STD_MB) {
			if (DEBUG)
				printf("[DEBUG][JUDGE:Output limit] used memory : %d\n", topmemory);
			result = OJ_ML;// Memory Limit
			ptrace(PTRACE_KILL, pid, NULL, NULL);
			break;
		}

		//check output limit(OJ_OL)
		if (get_file_size(conf.get_result_out()) > get_file_size(testcase_outfile_path.c_str()) * 20 && get_file_size(conf.get_result_out()) > 10000) {
			//OJ_OL은 2가지 조건을 충족해야 발생 result.out 파일의 크기가 [조건1) out파일 크기의 20배 초과 / 조건2) 1만바이트 초과]
			if (DEBUG)
				printf("[DEBUG][JUDGE:Output limit]\n");
			result = OJ_OL; // Output Limit
			ptrace(PTRACE_KILL, pid, NULL, NULL);
			break;
		}

		if (child_process_exit(pid, status, &result) == -1)//1.정상 종료 2.시그널 종료
			break;

		if (language > 3 && get_file_size(conf.get_runtime_error_txt()) > 0)
			result = OJ_RE;

		ptrace(PTRACE_GETREGS, pid, NULL, &reg);
		if (call_counter[language][reg.REG_SYSCALL]) {
			//if(DEBUG)
			//	printf("[DEBUG] allowed system call %llu",reg.REG_SYSCALL);
		}
		else {
			if (DEBUG)
				printf("[ERROR] not allowed system call : %llu\n", reg.REG_SYSCALL);
			result = OJ_SC;
			char error[BUFFER_SIZE];
			sprintf(error, "[Runtime Error] Not allowed system call, SYS_CALL ID : %ld\n", (long)reg.REG_SYSCALL);
			print_runtimeerror(error);
			ptrace(PTRACE_KILL, pid, NULL, NULL);
			break;
		}

		////////////////////////////////////////////////////////////////////////////////////////////////////
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL); //restart child proc
		//ptrace를 사용하는 이유는 중간중간 프로세스를 중단시켜서 OJ_OL,OJ_ML 등의 결과를 얻기 위함
	}//while(1)

	usedtime += (rus.ru_utime.tv_sec * 1000 + rus.ru_utime.tv_usec / 1000);
	usedtime += (rus.ru_stime.tv_sec * 1000 + rus.ru_stime.tv_usec / 1000);

	if (DEBUG)
		printf("[DEBUG] usedtime of run_program() : %d\n", usedtime);

	if (DEBUG)
		printf("[Info][watch_program() finish]\n");
	return result;
}//watch_program

int Run::child_process_exit(int pid, int status, int *result) {
	int exitcode, sig;


	//normal exited
	if (WIFEXITED(status)) {
		if (DEBUG)
			printf("normal exit\n");
		return -1;
	}//output limit check와 순서 변경

	exitcode = WEXITSTATUS(status); // 자식 프로세스가 정상 종료되었을 때 반환한 값

	// exitcode == 5 waiting for next CPU allocation(중간 상태 점검을 위해 중지시켰으므로), exitcode == 0 normal exit
	// lang = java, python / exitcode == 17 continue a stopped process
	if ((language >= 3 && exitcode == 17) || exitcode == 5 || exitcode == 0);
	else {// abnormal terminated
		if (DEBUG)
			printf("status>>8=%d\n", exitcode);

		if (*result == OJ_AC) {
			switch (exitcode) {
			case SIGCHLD: // 자식 프로세스 종료, 중단, 계속
			case SIGALRM: // 알람 클럭
				alarm(0);
			case SIGKILL: // 킬(신호를 잡거나 무시할 수 없음)
			case SIGXCPU: // CPU 제한 시간 초과
				*result = OJ_TL; // Time Limit
				break;
			case SIGXFSZ:	// 파일 크기 제한 초과
				*result = OJ_OL; // Output Limit
				break;
			default: // 위의 어떤 시그널 case에 해당 되지 않으면 Runtime error로 간주
				*result = OJ_RE; // Runtime Error
			}
			print_runtimeerror(strsignal(exitcode));//testcase_result에 바로 저장
		}//if
		ptrace(PTRACE_KILL, pid, NULL, NULL);
		return -1;
	}//else

	if (WIFSIGNALED(status)) {
		/*if the process is terminated by signal
		* sig = 5 means Trace/breakpoint trap
		* sig = 11 means Segmentation falut
		* sig = 25 means File size limit exceeded
		*/

		sig = WTERMSIG(status);

		if (DEBUG)
			printf("WTERMSIG=%d\n", sig);

		if (*result == OJ_AC) {
			switch (sig) {
			case SIGCHLD: // 자식 프로세스 종료, 중단, 계속
			case SIGALRM: // 알람 클럭
				alarm(0);
			case SIGKILL: // 킬(신호를 잡거나 무시할 수 없음)
			case SIGXCPU: // CPU 제한 시간 초과
				*result = OJ_TL; // Time Limit
				break;
			case SIGXFSZ: // 파일 크기 제한 초과
				*result = OJ_OL; // Output Limit
				break;
			default: // 위의 어떤 시그널 case에 해당 되지 않으면 Runtime error로 간주
				*result = OJ_RE; // Runtime Error
			}
			print_runtimeerror(strsignal(sig));
			if (DEBUG)
				printf("result = %d\n", *result);
		}//if
		return -1;
	}
}

void Run::init_syscalls_limits(int language) {
	char buffer[BUFFER_SIZE];
	FILE *fp;

	memset(call_counter, 0, sizeof(call_counter));
	switch (language) {
	case C_LANG:
	case CPP_LANG:
		fp = fopen("/home/ubuntu/new_worker/okcalls/C_okcalls_64bits.txt", "r");
		break;
	case JAVA:
		fp = fopen("/home/ubuntu/new_worker/okcalls/JAVA_okcalls_64bits.txt", "r");
		break;
	case PYTHON2:
		fp = fopen("/home/ubuntu/new_worker/okcalls/PYTHON2_okcalls_64bits.txt", "r");
		break;
	case PYTHON3:
		fp = fopen("/home/ubuntu/new_worker/okcalls/PYTHON3_okcalls_64bits.txt", "r");
		break;
	}

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		//printf("s: %s, atoi : %d\n", buffer, atoi(buffer));
		call_counter[language][atoi(buffer)] = OKCALL;
	}
	fclose(fp);
}


void Run::custom_set_limit_run()
{
	struct rlimit LIM;
	//---------------set time Limit----------------//
	LIM.rlim_cur = LIM.rlim_max = timeLimit + 1;
	setrlimit(RLIMIT_CPU, &LIM);//초 단위의 CPU 시간 제한
	alarm(0);
	alarm(timeLimit * 10);
	//---------------set memory Limit----------------//
	if (language == C_LANG || language == CPP_LANG) {
		LIM.rlim_cur = memoryLimit * STD_MB / 2 * 3;
		LIM.rlim_max = memoryLimit * STD_MB * 2;
		setrlimit(RLIMIT_AS, &LIM);//가상 메모리 제한
	}
	//---------------set file Limit----------------//
	LIM.rlim_max = STD_F_LIM + STD_MB;
	LIM.rlim_cur = STD_F_LIM;
	setrlimit(RLIMIT_FSIZE, &LIM);//최대 파일 크기 제한
	//---------------set proc Limit----------------//
	switch (language) {
	case JAVA:
		LIM.rlim_cur = LIM.rlim_max = 1000;
		break;
	case C_LANG:
	case CPP_LANG:
	case PYTHON2:
	case PYTHON3:
		LIM.rlim_cur = LIM.rlim_max = 1;
		break;
	}
	setrlimit(RLIMIT_NPROC, &LIM);//최대 프로세스 수 제한
	//----------set the stack Limit----------------//
	LIM.rlim_cur = STD_MB << 6;
	LIM.rlim_max = STD_MB << 6;
	setrlimit(RLIMIT_STACK, &LIM);//스택 메모리 제한
}

void Run::add_total_result(int final_judge_result, int max_usedtime, int max_topmemory) {
	FILE *user_fp;
	char buffer[BUFFER_SIZE];

	user_fp = fopen(conf.get_total_user(), "w");//최종 결과물

	sprintf(buffer, "%d%s%d%s%d", final_judge_result, conf.get_file_seperator(), max_usedtime, conf.get_file_seperator(), max_topmemory);
	fputs(buffer, user_fp);

	fclose(user_fp);
}

void Run::add_testcase_result(string testcase_name, int testcase_judge_result) {
	char buffer[BUFFER_SIZE];
	string command;
	string userout_path;
	FILE *name_result_fp;
	int temp;
	sprintf(buffer, "%d", testcase_judge_result);

	userout_path = conf.get_user_dir();
	userout_path = userout_path.append("/").append(testcase_name).append(".user");

	if (get_file_size(conf.get_result_out()) != 0) {
		if (copy_file(conf.get_result_out(), userout_path) == -1)
			return;
	}
	if (is_runtime_error_type(testcase_judge_result) && get_file_size(conf.get_runtime_error_txt()) != 0) {
		if ((temp = copy_file(conf.get_runtime_error_txt(), userout_path)) == -1)
			return;
	}

	printf("buffer : %s\n", buffer);
	name_result_fp = fopen(userout_path.c_str(), "a+");
	fputs(conf.get_file_seperator(), name_result_fp);
	fputs(buffer, name_result_fp);
	fclose(name_result_fp);
	//result 작성

	return;
}

bool Run::is_runtime_error_type(int testcase_judge_result) {
	return (testcase_judge_result == OJ_TL || testcase_judge_result == OJ_RE || testcase_judge_result == OJ_SC);
}

void Run::renew_record(int testcase_judge_result, int topmemory, int usedtime) {
	if (final_judge_result < testcase_judge_result) // 최종 결과(final_judge_result) 갱신
		final_judge_result = testcase_judge_result;

	if (max_usedtime <= usedtime)
		max_usedtime = usedtime;

	if (max_topmemory <= topmemory)
		max_topmemory = topmemory;

	if (DEBUG) {
		printf("testcase_judge_result : %d, finalResult : %d\n", testcase_judge_result, final_judge_result);
		printf("topmemory : %d, usedtime : %d\n", topmemory, usedtime);
		printf("max_topmemory : %d, max_usedtime : %d\n", max_topmemory, max_usedtime);
	}
}

int Run::get_proc_status(int pid, const char *mark) {
	FILE *pf;
	char fn[BUFFER_SIZE], buf[BUFFER_SIZE];
	int ret = 0;

	sprintf(fn, "/proc/%d/status", pid);
	pf = fopen(fn, "re");

	int m = strlen(mark);

	while (pf && fgets(buf, BUFFER_SIZE - 1, pf)) {
		buf[strlen(buf) - 1] = 0;
		if (strncmp(buf, mark, m) == 0) {
			sscanf(buf + m + 1, "%d", &ret);
			break;
		}
	}//while

	if (pf)
		fclose(pf);

	return ret;
}

int Run::get_page_fault_mem(struct rusage & ruse, pid_t & pidApp) {
	//java use pagefault
	int m_minflt;
	m_minflt = ruse.ru_minflt * getpagesize();

	return m_minflt;
}

long Run::get_file_size(const char *filename) {
	struct stat f_stat;

	if (stat(filename, &f_stat) == -1)
		return 0;

	return (long)f_stat.st_size;
}

int Run::execute_cmd(const char * fmt, ...) {
	char cmd[BUFFER_SIZE];

	int ret = 0;
	va_list ap;

	va_start(ap, fmt);
	vsprintf(cmd, fmt, ap);
	ret = system(cmd);
	va_end(ap);
	return ret;
}

void Run::print_runtimeerror(char * err) {
	FILE *fp;

	if (DEBUG)
		printf("RUNTIME ERROR!!!!!\n");

	fp = fopen("Runtime_Error.txt", "a+");
	fputs(err, fp);
	fclose(fp);
}

int Run::make_in_file_name_list(list<string> *testcase_name) {
	struct dirent *dirtestcase;
	int testcase_cnt = 0;
	int namelen = 0;
	char testcase_filename[BUFFER_SIZE];
	char testcase_outfile[BUFFER_SIZE];
	DIR *dp;

	if ((dp = opendir(conf.get_testcase_dir())) == NULL) {
		perror("can not open testcase directory, return OJ_ET\n");
		return 0;//workspace/testcase 디렉토리 자체가 없는 경우
	}

	//workspace/testcase 디렉토리 내부의 파일 개수를 체크한다.
	while ((dirtestcase = readdir(dp)) != NULL) {

		namelen = isInFile(dirtestcase->d_name);
		if (namelen == 0) //if namelen is 0, file is not .in file
			continue;

		strncpy(testcase_filename, dirtestcase->d_name, namelen);
		testcase_filename[namelen] = '\0';

		sprintf(testcase_outfile, "%s/%s.out", conf.get_testcase_dir(), testcase_filename);// -> /workspace/testcase/testcase_filename.out

		if (access(testcase_outfile, F_OK) == -1) //if .out file is not exist?
			continue;
		testcase_cnt++;

		testcase_name->push_back(testcase_filename);
		cout << "testcase filename :" << testcase_filename << endl;

		if (testcase_cnt == 0)
			return 0;
	}
	return testcase_cnt;
}

int Run::isInFile(char *inFname) {
	int len = strlen(inFname);
	if (len <= 3 || strcmp(inFname + len - 3, ".in") != 0)
		return 0;
	else
		return len - 3;
}

int Run::copy_file(string from_file, string to_file) {
	FILE *source_file = NULL, *destination_file = NULL;
	char buffer[BUFFER_SIZE];
	int n;

	if ((source_file = fopen(from_file.c_str(), "r")) == NULL) {
		printf("From file is not open\n");
		return -1;
	}
	if ((destination_file = fopen(to_file.c_str(), "a+")) == NULL) {
		printf("To file is not open\n");
		return -1;
	}


	while ((n = fread(buffer, sizeof(char), BUFFER_SIZE, source_file)) > 0) {
		fwrite(buffer, sizeof(char), n, destination_file);
	}

	fclose(source_file);
	fclose(destination_file);
	return 0;
}