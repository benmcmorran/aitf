#pragma once
#include <exception>
#include <string>

class AITFException : public std::runtime_error {
public:
	AITFException(const std::string& msg) : std::runtime_error(msg) {}
};