#include <iostream>
#include <string>

std::string test();

int main()
{
	std::cout << "App started!" << std::endl;
	std::cout << test();
	std::cout << "End!" << std::endl;
	
	return 0;
}
