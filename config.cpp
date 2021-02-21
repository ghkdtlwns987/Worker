#include "worker.h"

Config::Config() {
	FILE *fp = NULL;
	char buf[BUFFER_SIZE];
	this->work_dir[0] = 0;
	this->testcase_dir[0] = 0;
	this->java_xms[0] = 0;
	this->java_xmx[0] = 0;
	this->runtime_error_txt[0] = 0;
	this->compile_error_txt[0] = 0;
	this->result_out[0] = 0;
	this->total_user[0] = 0;
	this->user_dir[0] = 0;
	this->file_seperator[0] = 0;
	fp = fopen("./config/OJ.conf", "re");

	if (fp != NULL) {
		while (fgets(buf, BUFFER_SIZE - 1, fp)) {
			read_buf(buf, "OJ_WORK_DIR", work_dir);
			read_buf(buf, "OJ_TESTCASE_DIR", testcase_dir);
			read_buf(buf, "OJ_JAVA_XMS", java_xms);
			read_buf(buf, "OJ_JAVA_XMX", java_xmx);
			read_buf(buf, "OJ_RUNTIME_ERROR_TXT", runtime_error_txt);
			read_buf(buf, "OJ_COMPILE_ERROR_TXT", compile_error_txt);
			read_buf(buf, "OJ_RESULT_OUT", result_out);
			read_buf(buf, "OJ_TOTAL_USER", total_user);
			read_buf(buf, "OJ_USER_DIR", user_dir);
			read_buf(buf, "OJ_FILE_SEPERATOR",file_seperator);
		}
		fclose(fp);
	}//if(fp != NULL)
}//init_conf

char* Config::get_work_dir() {
	return work_dir;
}

char* Config::get_testcase_dir() {
	return testcase_dir;
}

char*Config::get_java_xms() {
	return java_xms;
}

char* Config::get_java_xmx() {
	return java_xmx;
}

char* Config::get_runtime_error_txt() {
	return runtime_error_txt;
}

char* Config::get_compile_error_txt() {
	return compile_error_txt;
}

char* Config::get_result_out() {
	return result_out;
}

char* Config::get_total_user() {
	return total_user;
}

char* Config::get_user_dir() {
	return user_dir;
}

char* Config::get_file_seperator() {
	return file_seperator;
}

int Config::after_equal(char * c) {
	int i = 0;
	for (; c[i] != '\0' && c[i] != '='; i++)
		;
	return ++i;
}

void Config::trim(char * c) {
	char buf[BUFFER_SIZE];
	char * start, *end;
	strcpy(buf, c);
	start = buf;
	while (isspace(*start))
		start++;
	end = start;
	while (!isspace(*end))
		end++;
	*end = '\0';
	strcpy(c, start);
}

bool Config::read_buf(char * buf, const char * key, char * value) {
	if (strncmp(buf, key, strlen(key)) == 0) {
		strcpy(value, buf + after_equal(buf));
		trim(value);
		return 1;
	}
	return 0;
}