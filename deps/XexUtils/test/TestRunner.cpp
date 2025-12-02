#include "pch.h"
#include "TestRunner.h"

#include "Console.h"

extern Console g_Console;

namespace TestRunner
{

struct TestCase
{
    std::string Name;
    TestFunction Function;
};

static size_t s_PassingTests;
static std::vector<std::string> s_ErrorMessages;
static std::vector<std::unordered_map<std::string, std::vector<TestCase>>> s_TestCases;
static std::string s_CurrentSectionName;

static void Run(const TestCase &testCase)
{
    std::wstringstream ss;

    // Indentation to properly show the tests under their sections
    ss << "    ";

    size_t previousFailCount = s_ErrorMessages.size();
    testCase.Function();
    size_t currentFailCount = s_ErrorMessages.size();

    if (currentFailCount == previousFailCount)
    {
        ss << GLYPH_X_MARK L"  " << testCase.Name.c_str();
        g_Console.Print(ss.str());
        s_PassingTests++;
    }
    else
    {
        ss << GLYPH_BIG_X L"  " << testCase.Name.c_str() << ". Error: " << s_ErrorMessages[s_ErrorMessages.size() - 1].c_str();
        g_Console.Print(ss.str());
    }
}

static void DisplayRecap()
{
    size_t failedTests = s_ErrorMessages.size();

    g_Console.Print(L"");

    if (failedTests > 0)
    {
        // Recap the error messages
        for (size_t i = 0; i < s_ErrorMessages.size(); i++)
        {
            std::wstringstream ss;
            ss << GLYPH_BIG_X L"  " << s_ErrorMessages[i].c_str();
            g_Console.Print(ss.str());
        }
        g_Console.Print(L"");
    }

    // Print the final recap
    std::stringstream ss;
    ss << s_PassingTests << " test" << (s_PassingTests != 1 ? "s" : "") << " passed, " << failedTests << " test" << (failedTests != 1 ? "s" : "") << " failed";
    g_Console.Print(ss.str());
}

void Describe(const std::string &sectionName)
{
    s_CurrentSectionName = sectionName;
}

void It(const std::string &testName, TestFunction testFunction)
{
    TestCase testCase = { testName, testFunction };

    // Look for an map for the current section and, if one exists, insert the test case
    // in its vector of test cases
    for (size_t i = 0; i < s_TestCases.size(); i++)
    {
        auto &map = s_TestCases[i];
        if (map.find(s_CurrentSectionName) != map.end())
        {
            map[s_CurrentSectionName].emplace_back(testCase);
            return;
        }
    }

    // If no map exists for the current section, create a new one and add it
    // to the list of maps
    std::unordered_map<std::string, std::vector<TestCase>> newMap;
    newMap[s_CurrentSectionName].emplace_back(testCase);
    s_TestCases.emplace_back(newMap);
}

void TestRunner::Run()
{
    // Go through all the maps
    for (size_t i = 0; i < s_TestCases.size(); i++)
    {
        // For each map, print its section names
        const auto &map = s_TestCases[i];
        for (auto it = map.begin(); it != map.end(); it++)
        {
            const std::string &sectionName = it->first;
            const std::vector<TestCase> &testCases = it->second;

            g_Console.Print(L"");
            g_Console.Print(sectionName);

            // For each section, run its test cases
            for (size_t i = 0; i < testCases.size(); i++)
                Run(testCases[i]);
        }
    }

    DisplayRecap();
}

void TestRunner::PushError(const std::string &errorMessage)
{
    s_ErrorMessages.push_back(errorMessage);
}

void PushError(const std::wstring &errorMessage)
{
    PushError(XexUtils::Formatter::ToNarrow(errorMessage));
}

}
