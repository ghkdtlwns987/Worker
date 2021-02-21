#include "worker.h"

int isScriptLanguage(int language)
{
	if ((language == PYTHON2) || (language == PYTHON3))
		return 1;
	else
		return 0;
}//스크립트 언어는 컴파일을 하지 않는다.


int main(int argc, char **argv) {
	int DEBUG = atoi(argv[1]);
	int language = atoi(argv[2]);
	int timeLimit = atoi(argv[3]);
	int memoryLimit = atoi(argv[4]);
	int result = 0;

	Config conf = Config();
	
	chdir(conf.get_work_dir());

	if (!isScriptLanguage(language)) {
		Compile compile = Compile(DEBUG, language, conf);
		result = compile.compile();
		if (result == -1)
			return -1;
	}

	Run run = Run(DEBUG, language, timeLimit / 1000, memoryLimit, conf);
	run.run();

	return 0;
}