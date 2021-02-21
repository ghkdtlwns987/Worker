#include "worker.h"

Compile::Compile(int DEBUG , int language ,Config conf) {
	this->DEBUG = DEBUG;
	this->language = language;
	this->conf = conf;
}

int Compile::compile() {
	FILE *fp;
	string str;

	if (DEBUG)
		printf("[Info][Compile start]\n");

	chdir(conf.get_work_dir());

	if (exec_compile(this->language) != 0) {
		fp = fopen(conf.get_total_user(), "w");
		fputs(compile_failed_result().c_str(), fp);
		fclose(fp);
		if(DEBUG)
			printf("[ERROR][Compile Error] : Compile application failed\n");
		copy_file(conf.get_compile_error_txt(), conf.get_total_user());
		return -1;
	}

	if (DEBUG) {
		printf("[Info][Compile finish]\n");
	}

	return 0;
}
int Compile::exec_compile(int language) {
	char buf[BUFFER_SIZE];
	FILE* errorfd;
	pid_t pid;

	const char * CP_C[] = { "gcc", "-o", "Main", "Main.c", "-lm", "-std=c99", "-static", "-fno-asm", "-Wall", NULL };
	const char * CP_CPP[] = { "g++", "-o", "Main", "Main.cpp", "-fno-asm", "-Wall", "-lm", "-std=c++11", "-static", NULL };

	char javac_buf[7][16];
	char *CP_JAVA[7];

	for (int i = 0; i < 7; i++)
		CP_JAVA[i] = javac_buf[i];

	sprintf(CP_JAVA[0], "javac");
	sprintf(CP_JAVA[1], "-J%s", conf.get_java_xms());
	sprintf(CP_JAVA[2], "-J%s", conf.get_java_xmx());
	sprintf(CP_JAVA[3], "-encoding");
	sprintf(CP_JAVA[4], "UTF-8");
	sprintf(CP_JAVA[5], "Main.java");
	CP_JAVA[6] = (char *)NULL;


	if (DEBUG) {
		printf("Compile command : ");
		switch (language) {
		case C_LANG:
			for (int i = 0; CP_C[i] != NULL; i++)
				printf("%s ", CP_C[i]);
			break;
		case CPP_LANG:
			for (int i = 0; CP_CPP[i] != NULL; i++)
				printf("%s ", CP_CPP[i]);
			break;
		case JAVA:
			for (int i = 0; CP_JAVA[i] != NULL; i++)
				printf("%s ", CP_JAVA[i]);
		}//switch
		printf("\n");
	}

	 // child -> compile
	 // parent -> wait & fetch result & return result
	if ((pid = fork()) == 0) { // child가 컴파일

		custom_set_limit_compile(language);

		errorfd = freopen(conf.get_compile_error_txt(), "w", stderr);

		while (setgid(1000) != 0) sleep(1);
		while (setuid(1000) != 0) sleep(1);
		while (setresuid(1000, 1000, 1000) != 0) sleep(1);

		switch (language) {
		case C_LANG:
			execvp(CP_C[0], (char * const *)CP_C);
			break;
		case CPP_LANG:
			execvp(CP_CPP[0], (char * const *)CP_CPP);
			break;
		case JAVA:
			execvp(CP_JAVA[0], (char * const *)CP_JAVA);
			break;
		}

		if (DEBUG)
			perror("[ERROR][Compile error] : execvp() failed\n");

		fclose(errorfd);
		//unnormal exit
		exit(1);
	}//if
	else {
		int status = 0;
		waitpid(pid, &status, 0);
		if (DEBUG)
			printf("[DEBUG][Compile]status = %d\n", status);
		return status;//컴파일 성공 시 0 반환
	}//else
}

void Compile::custom_set_limit_compile(int language) {
	struct rlimit LIM;

	//cpu using time : 60s
	LIM.rlim_max = 60;
	LIM.rlim_cur = 60;
	setrlimit(RLIMIT_CPU, &LIM);
	alarm(60);

	//max file size : 100MB
	LIM.rlim_max = 100 * STD_MB;
	LIM.rlim_cur = 100 * STD_MB;
	setrlimit(RLIMIT_FSIZE, &LIM);

	//max virtual memory size
	if (language == JAVA) {
		LIM.rlim_max = STD_MB << 11;
		LIM.rlim_cur = STD_MB << 11;
	}
	else {
		LIM.rlim_max = STD_MB << 10;
		LIM.rlim_cur = STD_MB << 10;
	}
	setrlimit(RLIMIT_AS, &LIM);
}

int Compile::copy_file(string from_file, string to_file) {
	FILE *source_file = NULL, *destination_file = NULL;
	char buffer[BUFFER_SIZE];
	int n;

	if ((source_file = fopen(from_file.c_str(), "r")) == NULL) {
		printf("[ERROR][Compile::copy_file() Error] : From file is not open\n");
		return -1;
	}
	if ((destination_file = fopen(to_file.c_str(), "a+")) == NULL) {
		printf("[ERROR][Compile::copy_file() Error] : To file is not open\n");
		return -1;
	}


	while ((n = fread(buffer, sizeof(char), BUFFER_SIZE, source_file)) > 0) {
		fwrite(buffer, sizeof(char), n, destination_file);
	}

	fclose(source_file);
	fclose(destination_file);
	return 0;
}

string Compile::compile_failed_result() {
	string buffer;
	buffer = to_string(OJ_CE).append(conf.get_file_seperator()).append("0").append(conf.get_file_seperator()).append("0").append(conf.get_file_seperator());
	return buffer;
}
