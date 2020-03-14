#include <string>

const char *const s0 = "s3.amazonaws.com";
const char *const s1 = ".s3.amazonaws.com/";
const char *const s2 = ".s3.amazonaws.com";
const char *const s3 = "https://s3.amazonaws.com/";
const char *const s4 = "us-east-1";

std::string foo(const char *const a, const char *const b)
{
	return std::string(a) + std::string(b);
}

std::string test()
{
	std::string x;
	
	x += foo("String \"s3.amazonaws.com\": ",          s0) + '\n';
	x += foo("String \".s3.amazonaws.com/\": ",        s1) + '\n';
	x += foo("String \".s3.amazonaws.com\": ",         s2) + '\n';
	x += foo("String \"https://s3.amazonaws.com/\": ", s3) + '\n';
	x += foo("String \"us-east-1\": ",                 s4) + '\n';
	
	return x;
}
