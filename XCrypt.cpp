// XCrypt.cpp : Defines the entry point for the console application.
// v.0.3.5

#include "stdafx.h"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <Windows.h>
#include <random>
#define MB 1048576

using namespace std;

class Clock
{
public:

	Clock(short hour = 0, short minute = 0, short second = 0) : hour(hour), minute(minute), second(second) {}
	void setCurrent();
	friend ostream &operator<<(ostream &stream, Clock object);
	Clock &operator=(const Clock &object);
	Clock Clock::operator-(const Clock &object);

private:

	short hour;
	short minute;
	short second;
};

void Clock::setCurrent()
{
	time_t rawTime = time(NULL);
	tm timeInfo;
	localtime_s(&timeInfo, &rawTime);
	hour = timeInfo.tm_hour;
	minute = timeInfo.tm_min;
	second = timeInfo.tm_sec;
}

ostream &operator<<(ostream &stream, Clock object)
{
	stream << setfill('0') << setw(2) << object.hour << ':';
	stream << setfill('0') << setw(2) << object.minute << ':';
	stream << setfill('0') << setw(2) << object.second;
	return stream;
}

Clock &Clock::operator=(const Clock &object)
{
	hour = object.hour;
	minute = object.minute;
	second = object.second;
	return *this;
}

Clock Clock::operator-(const Clock &object)
{
	Clock temp;
	temp.second += second - object.second;
	if (temp.second < 0)
	{
		temp.second += 60;
		temp.minute--;
	}
	temp.minute += minute - object.minute;
	if (temp.minute < 0)
	{
		temp.minute += 60;
		temp.hour--;
	}
	temp.hour += hour - object.hour;
	if (temp.hour < 0)
		temp.hour += 24;
	return temp;
}



class CryptFile
{
public:

	CryptFile(unsigned int bufferSize = MB);
	CryptFile(string path, unsigned int bufferSize);
	~CryptFile();
	void open(char *path);
	void open(string &path);
	void close();
	void setBuffer(unsigned int size);
	void setPassword(string password);
	void encryptionStateCheck(bool mode);
	void addNewExtension(bool mode);
	void enableSecureErase(bool mode);
	void enableSecureEraseEcho(bool mode);
	void encrypt();
	void decrypt();
	void erase();
	bool remove();
	bool isError();

private:

	void openHelper(const char* path);
	void initializeNullBuffer();
	bool createFile();
	void setSeed();
	void cryptAlgorithm(char* buffer, streamoff size);
	void crypt();
	void writeUnlock();
	void secureErase();
	void replaceOriginal(char mode);

	enum { ENCRYPT, DECRYPT };
	static const unsigned int nullBufferSize;
	static unsigned int objectCounter;
	fstream originalFile;
	fstream newFile;
	string name;
	string password;
	char* buffer;
	static char* nullBuffer;
	streamoff bufferSize;
	streamoff fileSize;
	size_t passHash;
	mt19937 randGenerator;
	bool isEncryptionStateCheck;
	bool isNewExtension;
	bool isSecureErase;
	bool isSecureEraseEcho;
	bool errorFlag;
};

const unsigned int CryptFile::nullBufferSize = 1024;
unsigned int CryptFile::objectCounter = 0;
char* CryptFile::nullBuffer = NULL;

CryptFile::CryptFile(unsigned int bufferSize) : isEncryptionStateCheck(true), isNewExtension(true), isSecureErase(true), isSecureEraseEcho(true), errorFlag(false)
{
	this->bufferSize = bufferSize;
	buffer = new char[this->bufferSize];
	if (!objectCounter)
		initializeNullBuffer();
	objectCounter++;
}

CryptFile::CryptFile(string path, unsigned int bufferSize): isEncryptionStateCheck(true), isNewExtension(true), isSecureErase(true), isSecureEraseEcho(true)
{
	openHelper(path.c_str());
	if (bufferSize <= fileSize)
		this->bufferSize = bufferSize;
	else
		this->bufferSize = fileSize;
	buffer = new char[this->bufferSize];
	if (!objectCounter)
		initializeNullBuffer();
	objectCounter++;
}

CryptFile::~CryptFile()
{
	delete[] buffer;
	if (objectCounter == 1)
		delete[] nullBuffer;
	objectCounter--;
}

void CryptFile::open(char *path)
{
	openHelper(path);
}

void CryptFile::open(string &path)
{ 
	openHelper(path.c_str());
}

void CryptFile::setBuffer(unsigned int size)
{
	delete[] buffer;
	bufferSize = size;
	buffer = new char[this->bufferSize];
}

void CryptFile::setPassword(string password)
{
	this->password = password;
	hash<string> hashFn;
	this->passHash = hashFn(password);
}

void CryptFile::encryptionStateCheck(bool mode = true)
{
	isEncryptionStateCheck = mode;
}

void CryptFile::addNewExtension(bool mode = true)
{
	isNewExtension = mode;
}

void CryptFile::enableSecureErase(bool mode = true)
{
	isSecureErase = mode;
}

void CryptFile::enableSecureEraseEcho(bool mode = true)
{
	isSecureEraseEcho = mode;
}

void CryptFile::encrypt()
{
	if (isEncryptionStateCheck && name.find(".xcr") != string::npos)
	{
		cerr << "Error: File already encrypted." << endl;
		errorFlag = true;
		return;
	}
	originalFile.seekg(0, ios::beg);
	crypt();
	char encryptedPass[256];
	strcpy_s(encryptedPass, password.c_str());
	setSeed();
	cryptAlgorithm(encryptedPass, password.length());
	newFile.write(encryptedPass, password.length());
	replaceOriginal(ENCRYPT);
}

void CryptFile::decrypt()
{
	streamoff offset = 0;
	offset -= password.length();
	originalFile.seekg(offset, ios::end);
	char encryptedPass[256];
	originalFile.read(encryptedPass, password.length());
	setSeed();
	cryptAlgorithm(encryptedPass, password.length());
	encryptedPass[password.length()] = '\0';
	if (password != encryptedPass)
	{
		cerr << "Error: Incorrect password." << endl;
		errorFlag = true;
		return;
	}
	originalFile.seekg(0, ios::beg);
	fileSize += offset;
	crypt();
	replaceOriginal(DECRYPT);
}

void CryptFile::erase()
{
	writeUnlock();
	secureErase();
	close();
	remove();
}

bool CryptFile::remove()
{
	return DeleteFileA(name.c_str()) == TRUE;
}

void CryptFile::close()
{
	originalFile.close();
	newFile.close();
}

bool CryptFile::isError()
{
	return errorFlag;
}

void CryptFile::openHelper(const char* path)
{
	errorFlag = false;
	originalFile.open(path, ios::in | ios::binary | ios::ate);
	if (!originalFile.is_open())
	{
		cerr << "Error: File not found." << endl;
		errorFlag = true;
		return;
	}
	name = path;
	fileSize = originalFile.tellg();
}

void CryptFile::initializeNullBuffer()
{
	nullBuffer = new char[nullBufferSize];
	for (unsigned int i = 0; i < nullBufferSize; i++)
		nullBuffer[i] = '\0';
}

bool CryptFile::createFile()
{
	string newFileName = name + "~";
	newFile.open(newFileName.c_str(), ios::out | ios::binary | ios::trunc);
	return newFile.is_open() ? true : false;
}

void CryptFile::setSeed()
{
	randGenerator.seed(static_cast<unsigned int>(passHash % UINT_MAX));
}

void CryptFile::cryptAlgorithm(char* buffer, streamoff size)
{
	size_t passwordLength = password.length();
	char pass[255];
	strcpy_s(pass, password.c_str());
	for (streamoff i = 0; i < size; i++)
		buffer[i] ^= static_cast<char>(pass[i % passwordLength] * randGenerator());
}

void CryptFile::crypt()
{
	streamoff tokens = fileSize / bufferSize;
	streamoff remainder = fileSize % bufferSize;
	if (!createFile())
	{
		cerr << "Error: Write to Disk: Access Denied." << endl;
		cerr << "Error code: " << GetLastError() << endl;
		errorFlag = true;
		return;
	}
	setSeed();
	for (streamoff i = 0; i < tokens; i++)
	{
		originalFile.read(buffer, bufferSize);
		cryptAlgorithm(buffer, bufferSize);
		newFile.write(buffer, bufferSize);
	}
	if (remainder)
	{
		originalFile.read(buffer, remainder);
		cryptAlgorithm(buffer, remainder);
		newFile.write(buffer, remainder);
	}
}

void CryptFile::writeUnlock()
{
	WIN32_FIND_DATAA findData;
	HANDLE hFind = FindFirstFileA(name.c_str(), &findData);
	SetFileAttributesA(name.c_str(), findData.dwFileAttributes & ~(FILE_ATTRIBUTE_READONLY));
	FindClose(hFind);
}

void CryptFile::secureErase()
{
	fstream file(name, ios::out | ios::ate | ios::binary);
	if (!file)
	{
		cerr << "Error: File not found." << endl;
		errorFlag = true;
		return;
	}
	streamoff tokens = fileSize / nullBufferSize;
	streamoff remainder = fileSize % nullBufferSize;
	file.seekg(0, ios::beg);
	if (isSecureEraseEcho)
		cout << "Erasing unencrypted file..." << endl;
	for (streamoff i = 0; i < tokens; i++)
		file.write(nullBuffer, nullBufferSize);
	if (remainder)
		file.write(nullBuffer, remainder);
	file.close();
}

void CryptFile::replaceOriginal(char mode)
{
	close();
	writeUnlock();
	if (mode == ENCRYPT && isSecureErase)
		secureErase();
	if (!remove())
	{
		cerr << "Error: Failed to delete file." << endl;
		cerr << "Error code: " << GetLastError() << endl;
		errorFlag = true;
		return;
	}
	string oldFileName = name + "~";
	bool isNameChanged = true;
	if (mode == ENCRYPT && isNewExtension)
		name += ".xcr";
	else if (mode == DECRYPT && isNewExtension)
	{
		size_t position = name.find(".xcr");
		if (position != string::npos)
			name.resize(position);
		else
			isNameChanged = false;
	}
	if (!MoveFileA(oldFileName.c_str(), name.c_str()))
	{
		cerr << "Error: Failed to rename files." << endl;
		cerr << "Error code: " << GetLastError() << endl;
		errorFlag = true;
	}
	if (isNewExtension && isNameChanged)
		cout << "New file name: " << name << endl;
}



class CryptFolder
{
public:

	CryptFolder();
	CryptFolder(unsigned int size);
	CryptFolder(string& path);
	void setBuffer(unsigned int size);
	void open(string& path);
	void setPassword(string &password);
	void encrypt();
	void decrypt();
	void erase();
	void enableSecureErase(bool mode);
	void enableEncryptionStateCheck(bool mode);
	void includeSystemFiles(bool mode = true);
	bool isError();

private:

	bool baseCrypt(string& path, char mode);
	bool FileExists(string & fname);
	void crypt(string path, char mode);
	void renameFiles(string& path, char mode);

	enum { ENCRYPT, DECRYPT, ERASE };
	CryptFile file;
	string folderPath;
	string password;
	WIN32_FIND_DATAA findData;
	bool includeSysFiles;
	bool isEncryptionStateCheck;
	bool errorFlag;
};

CryptFolder::CryptFolder() : file(64 * MB), includeSysFiles(false), isEncryptionStateCheck(true), errorFlag(false)
{
	file.encryptionStateCheck(false);
	file.addNewExtension(false);
}

CryptFolder::CryptFolder(unsigned int bufferSize) : file(bufferSize), includeSysFiles(false), isEncryptionStateCheck(true), errorFlag(false)
{
	file.encryptionStateCheck(false);
	file.addNewExtension(false);
}

CryptFolder::CryptFolder(string &path) : file(64 * MB), includeSysFiles(false), isEncryptionStateCheck(true), errorFlag(false)
{
	file.encryptionStateCheck(false);
	file.addNewExtension(false);
	open(path);
}

void CryptFolder::setBuffer(unsigned int size)
{
	file.setBuffer(size);
}

void CryptFolder::open(string & path)
{
	folderPath = path;
	if (folderPath[folderPath.length() - 1] != '\\')
		folderPath.insert(folderPath.length(), "\\");
}

void CryptFolder::setPassword(string &password)
{
	file.setPassword(password);
	this->password = password;
}

void CryptFolder::encrypt()
{
	file.enableSecureEraseEcho(true);
	crypt(folderPath, ENCRYPT);

}

void CryptFolder::decrypt()
{
	file.enableSecureEraseEcho(true);
	crypt(folderPath, DECRYPT);
}

void CryptFolder::erase()
{
	file.enableSecureEraseEcho(false);
	crypt(folderPath, ERASE);
}

void CryptFolder::enableSecureErase(bool mode = true)
{
	file.enableSecureErase(mode);
}

void CryptFolder::enableEncryptionStateCheck(bool mode = true)
{
	isEncryptionStateCheck = mode;
}

void CryptFolder::includeSystemFiles(bool mode)
{
	includeSysFiles = mode;
}

bool CryptFolder::isError()
{
	return file.isError() || errorFlag;
}

bool CryptFolder::baseCrypt(string& path, char mode)
{
	CryptFile base(path, 1);
	base.setPassword(password);
	base.enableSecureEraseEcho(false);
	base.encryptionStateCheck(false);
	base.addNewExtension(false);
	switch (mode)
	{
	case ENCRYPT:
		base.encrypt();
		break;
	case DECRYPT:
		base.decrypt();
		break;
	}
	base.close();
	return !base.isError();
}

bool CryptFolder::FileExists(string& fname)
{
	WIN32_FIND_DATAA wfd;
	HANDLE hFind = FindFirstFileA(fname.c_str(), &wfd);
	if (INVALID_HANDLE_VALUE != hFind)
	{
		FindClose(hFind);
		return true;
	}
	return false;
}

void CryptFolder::crypt(string path, char mode)
{
	ofstream nameBase;
	string basePath = path + "data.xcr";
	if (mode == ENCRYPT)
	{
		if (isEncryptionStateCheck && FileExists(basePath))
		{
			cerr << "Error: Folder already encrypted." << endl;
			errorFlag = true;
			return;
		}
		nameBase.open(basePath);
		if (!nameBase)
		{
			cerr << "Error: Failed to create database." << endl;
			exit(EXIT_SUCCESS);
		}
	}
	else if (mode == DECRYPT)
	{
		if (isEncryptionStateCheck && !FileExists(basePath))
		{
			cerr << "Error: Database doesn't exist. Files will not be decrypted." << endl;
			errorFlag = true;
			return;
		}
		if (!baseCrypt(basePath, DECRYPT))
		{
			errorFlag = true;
			return;
		}
		renameFiles(path, DECRYPT);
		if (!DeleteFileA(basePath.c_str()))
		{
			cerr << "Error: Failed to remove database";
			cerr << "Error code: " << GetLastError() << endl;
			errorFlag = true;
		}
	}
	string folderPathFormat = path + "*";
	HANDLE hFind = FindFirstFileA(folderPathFormat.c_str(), &findData);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		cerr << "Error: Invalid folder path." << endl;
		cerr << "Error code: " << GetLastError() << endl;
		errorFlag = true;
		return;
	}
	unsigned int fileCounter = 0, folderCounter = 0;
	do
	{
		string currentFilePath = path + findData.cFileName;
		if ((findData.cFileName[0] == '.' && strlen(findData.cFileName) <= 2) ||
			(mode != ERASE && !strcmp(findData.cFileName, "data.xcr")) ||
			(!includeSysFiles && (findData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)))
			continue;
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (mode == ENCRYPT && !strstr(findData.cFileName, "~F_XCR_"))
			{
				nameBase << "~F_XCR_" << folderCounter << '|';
				nameBase << findData.cFileName << endl;
				folderCounter++;
			}
			crypt(currentFilePath + "\\", mode);
			continue;
		}
		cout << "Current file: " << currentFilePath << endl;
		file.open(currentFilePath);
		switch (mode)
		{
		case ENCRYPT:
			file.encrypt();
			nameBase << fileCounter << ".xcr|";
			nameBase << findData.cFileName << endl;
			break;
		case DECRYPT:
			file.decrypt();
			break;
		case ERASE:
			file.erase();
			break;
		default:
			cerr << "Error: Incorrect mode" << endl;
			errorFlag = true;
		}
		fileCounter++;
	} while (FindNextFileA(hFind, &findData));
	FindClose(hFind);
	if (mode == ENCRYPT)
	{
		nameBase.close();
		renameFiles(path, ENCRYPT);
		if (!baseCrypt(basePath, ENCRYPT))
		{
			cerr << "Error: Failed to encrypt database." << endl;
			errorFlag = true;
		}
	}
	else if (mode == ERASE)
		if (!RemoveDirectoryA(path.c_str()))
		{
			cerr << "Error: Failed to remove folder." << endl;
			cerr << "Error code: " << GetLastError() << endl;
			errorFlag = true;
		}
}

void CryptFolder::renameFiles(string& path, char mode)
{
	ifstream nameBase(path + "data.xcr");
	if (!nameBase)
	{
		cerr << "Error: Database not found." << endl;
		errorFlag = true;
		return;
	}
	while (!nameBase.eof())
	{
		char encryptedName[128], originalName[128];
		nameBase.get(encryptedName, 128, '|');
		nameBase.ignore();
		nameBase.getline(originalName, 128, '\n');
		string encryptedNamePath = path + encryptedName;
		string originalNamePath = path + originalName;
		if (!(mode == ENCRYPT ? MoveFileA(originalNamePath.c_str(), encryptedNamePath.c_str()) : MoveFileA(encryptedNamePath.c_str(), originalNamePath.c_str())))
		{
			cerr << "Error: Failed to rename file: " << originalName << endl;
			cerr << "Error code: " << GetLastError() << endl;
			errorFlag = true;
		}
		if (nameBase.peek() == '\n')
			nameBase.ignore();
	}
	nameBase.close();
}



void Help()
{
	cout << "USAGE:" << endl;
	cout << "xcrypt [/? | /e | /d | /r | /a | /s | /k | /u | /i | /p] path [password]" << endl;
	cout << "/?		Display help." << endl;
	cout << "/e		Encrypt." << endl;
	cout << "/d		Decrypt." << endl;
	cout << "/r		Erase." << endl;
	cout << "/a		Erase without confirmation (unsafe key)." << endl;
	cout << "/s		Include system files (folder encryption mode only)." << endl;
	cout << "/k		Keep file extension (file encryption mode only)." << endl;
	cout << "/u		Disable secure erase (unsafe key)." << endl;
	cout << "/i		Ignore encryption state (folder encryption mode only)." << endl;
	cout << "/p		Enable pause after operations." << endl;
	cout << "Use a separate slash for each key.\n" << endl;
#ifdef _WIN64
	cout << "Note: XCrypt x64 is not compatible with files, created by XCrypt x86.";
#else
	cout << "Note: XCrypt x86 is not compatible with files, created by XCrypt x64.";
#endif
}

void ConsoleError()
{
	cerr << "Error: Incorrect values.\n" << endl;
	Help();
	exit(EXIT_FAILURE);
}

string GetPassword(bool showAsterisk = true)
{
	const char BACKSPACE = 8, RETURN = 13;
	string password;
	unsigned char ch = 0;
	DWORD con_mode, dwRead;
	HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(hIn, &con_mode);
	SetConsoleMode(hIn, con_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));
	while (ReadConsoleA(hIn, &ch, 1, &dwRead, NULL) && ch != RETURN)
	{
		if (ch == BACKSPACE)
		{
			if (password.length())
			{
				if (showAsterisk)
					cout << "\b \b";
				password.resize(password.length() - 1);
			}
		}
		else
		{
			password += ch;
			if (showAsterisk)
				cout << '*';
		}
	}
	cout << endl;
	SetConsoleMode(hIn, con_mode);
	return password;
}

bool CheckPassword(string& password, unsigned int tryNumber = 3, bool isConfirmation = true)
{
	string confirmation;
	for (unsigned int i = 0; i < tryNumber; i++)
	{
		if (i)
			cout << "Passwords don't match. Try again." << endl;
		cout << "Enter password: ";
		password = GetPassword();
		if (!isConfirmation)
			return true;
		cout << "Confirm password: ";
		confirmation = GetPassword();
		if (password == confirmation)
			return true;
	}
	return false;
}

int main(int argc, char *argv[])
{
	ios_base::sync_with_stdio(false);
#ifdef _WIN64
	cout << "XCrypt v.0.3.5 x64, 2015\n" << endl;
#else
	cout << "XCrypt v.0.3.5 x86, 2015\n" << endl;
#endif
	setlocale(LC_ALL, "Ukrainian");
	enum { FILE, DIRECTORY, UNDEFINED };
	enum
	{
		ENCRYPT,
		DECRYPT,
		ENCRYPT_WITH_SYSTEM_FILES = 2,
		ENCRYPT_WITHOUT_SECURE_ERASE = 2,
		DECRYPT_WITH_SYSTEM_FILES,
		ERASE,
		ERASE_WITHOUT_CONFIRMATION,
		ERASE_WITH_SYSTEM_FILES
	};
	char fileType = UNDEFINED, mode = UNDEFINED, c;
	bool isPause = false, isPassAsCmdArg = false;
	WIN32_FIND_DATAA findData;
	CryptFile file(4);
	CryptFolder folder(4);
	string path, password;
	char **argvPtr = argv;
	int argcCopy = argc;
	short correctArgsCounter = 0, slashCounter = 0;
	if (argc > 1)
	{
		while (--argc > 0 && (*++argv)[0] == '/')
		{
			while (c = *++argv[0])
				switch (c)
				{
				case 'e':
					if (mode != UNDEFINED)
						ConsoleError();
					mode = ENCRYPT;
					correctArgsCounter++;
					break;
				case 'd':
					if (mode != UNDEFINED)
						ConsoleError();
					mode = DECRYPT;
					correctArgsCounter++;
					break;
				case 'r':
					if (mode != UNDEFINED)
						ConsoleError();
					mode = ERASE;
					correctArgsCounter++;
					break;
				case 'a':
					if (mode != UNDEFINED)
						ConsoleError();
					mode = ERASE_WITHOUT_CONFIRMATION;
					correctArgsCounter++;
					break;
				case 's':
					folder.includeSystemFiles();
					correctArgsCounter++;
					break;
				case 'i':
					folder.enableEncryptionStateCheck(false);
					correctArgsCounter++;
					break;
				case 'k':
					file.addNewExtension(false);
					correctArgsCounter++;
					break;
				case 'p':
					isPause = true;
					correctArgsCounter++;
					break;
				case 'u':
					file.enableSecureErase(false);
					folder.enableSecureErase(false);
					correctArgsCounter++;
					break;
				case '?':
					Help();
					exit(EXIT_SUCCESS);
				default:
					ConsoleError();
				}
			slashCounter++;
		}
		if (mode == UNDEFINED || argcCopy - slashCounter == 1 || slashCounter != correctArgsCounter)
			ConsoleError();
		if (mode < ERASE && argcCopy - correctArgsCounter == 3)
		{
			path = argvPtr[argcCopy - 2];
			password = argvPtr[argcCopy - 1];
			isPassAsCmdArg = true;
		}
		else
			path = argvPtr[argcCopy - 1];
	}
	else
	{
		cout << "Path to file/folder: ";
		getline(cin, path);
	}
	cout << "Checking..." << endl;
	HANDLE hFind = FindFirstFileA(path.c_str(), &findData);
	if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(findData.dwFileAttributes & FILE_ATTRIBUTE_DEVICE))
	{
		file.setBuffer(64 * MB);
		file.open(path);
		if (file.isError())
		{
			if (argcCopy == 1 || isPause)
				system("pause");
			exit(EXIT_FAILURE);
		}
		fileType = FILE;
	}
	else
	{
		folder.setBuffer(128 * MB);
		folder.open(path);
		fileType = DIRECTORY;
	}
	cout << "Complete." << endl;
	if (argcCopy > 1 && !isPassAsCmdArg && mode < ERASE)
	{
		if (mode == DECRYPT)
			CheckPassword(password, 1, false);
		else if (!CheckPassword(password))
			exit(EXIT_FAILURE);
	}
	if (argcCopy == 1)
	{
		cout << "Choose an option:" << endl;
		if (fileType == FILE)
			cout << "1 - Encrypt file		2 - Decrypt file		3 - Erase file\n->: ";
		else
		{
			cout << "1 - Encrypt folder" << endl;
			cout << "2 - Decrypt folder" << endl;
			cout << "3 - Encrypt folder (include system files)" << endl;
			cout << "4 - Decrypt folder (include system files)" << endl;
			cout << "5 - Erase folder" << endl;
			cout << "6 - Erase folder (include system files)\n->: ";
		}
		cin >> mode;
		mode -= 0x31;
		if (fileType == FILE && mode == 2)
			mode = ERASE;
		else if (fileType == DIRECTORY && mode == 5)
			mode = ERASE_WITH_SYSTEM_FILES;
		if (mode < ERASE)
			if (mode == DECRYPT || mode == DECRYPT_WITH_SYSTEM_FILES)
				CheckPassword(password, 1, false);
			else if (!CheckPassword(password))
			{
				system("pause");
				exit(EXIT_FAILURE);
			}
	}
	Clock startTime;
	startTime.setCurrent();
	switch (fileType)
	{
	case FILE:
	{
		file.setPassword(password);
		switch (mode)
		{
		case ENCRYPT_WITHOUT_SECURE_ERASE:
			file.enableSecureErase(false);
		case ENCRYPT:
			cout << "Encrypting file..." << endl;
			file.encrypt();
			break;
		case DECRYPT:
			cout << "Decrypting file..." << endl;
			file.decrypt();
			break;
		case ERASE:
			char eraseOption;
			cout << "Are you sure want to erase file? (y/n): ";
			cin >> eraseOption;
			if (eraseOption == 'y' || eraseOption == 'Y')
			{
				cout << "Erasing file..." << endl;
				file.enableSecureEraseEcho(false);
				startTime.setCurrent();
				file.erase();
			}
			else
			{
				cout << "Erasing canceled." << endl;
				if (argcCopy == 1 || isPause)
					system("pause");
				exit(EXIT_SUCCESS);
			}
			break;
		case ERASE_WITHOUT_CONFIRMATION:
			cout << "Erasing file..." << endl;
			file.enableSecureEraseEcho(false);
			file.erase();
			break;
		default:
			cerr << "Error: Incorrect input value." << endl;
			if (argcCopy == 1 || isPause)
				system("pause");
			exit(EXIT_SUCCESS);
		}
	}
	break;
	case DIRECTORY:
	{
		folder.setPassword(password);
		switch (mode)
		{
		case ENCRYPT_WITH_SYSTEM_FILES:
			folder.includeSystemFiles();
		case ENCRYPT:
			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DEVICE)
			{
				cout << "You're going to encrypt device. Are you sure you're not drunk?" << endl;
				cout << "1 - No, I'd better go to bed		2 - JUST DO IT!!!\n->: ";
				int drugOption;
				cin >> drugOption;
				if (drugOption == 1)
					exit(EXIT_SUCCESS);
				if (drugOption != 1 && drugOption != 2)
				{
					cout << "Incorrect input, my drunk friend." << endl;
					if (argcCopy == 1 || isPause)
						system("pause");
					exit(EXIT_SUCCESS);
				}
			}
			cout << "Encrypting folder..." << endl;
			folder.encrypt();
			break;
		case DECRYPT_WITH_SYSTEM_FILES:
			folder.includeSystemFiles();
		case DECRYPT:
			cout << "Decrypting the folder..." << endl;
			folder.decrypt();
			break;
		case ERASE_WITH_SYSTEM_FILES:
			folder.includeSystemFiles();
		case ERASE:
			char eraseOption;
			cout << "Are you sure want to erase folder? (y/n): ";
			cin >> eraseOption;
			if (eraseOption == 'y' || eraseOption == 'Y')
			{
				cout << "Erasing folder..." << endl;
				startTime.setCurrent();
				folder.erase();
			}
			else
			{
				cout << "Erasing canceled." << endl;
				if (argcCopy == 1 || isPause)
					system("pause");
				exit(EXIT_SUCCESS);
			}
			break;
		case ERASE_WITHOUT_CONFIRMATION:
			cout << "Erasing folder..." << endl;
			folder.erase();
			break;
		default:
			cerr << "Error: Incorrect input value." << endl;
			if (argcCopy == 1 || isPause)
				system("pause");
			exit(EXIT_SUCCESS);
		}
	}
	break;
	}
	FindClose(hFind);
	if ((fileType == FILE && !file.isError()) || (fileType == DIRECTORY && !folder.isError()))
		cout << "Finished." << endl;
	else if (fileType == DIRECTORY)
		cerr << "Error while processing some files/folders." << endl;
	Clock currentTime;
	currentTime.setCurrent();
	cout << "Time elapsed: " << currentTime - startTime << '.' << endl;
	if (argcCopy == 1 || isPause)
		system("pause");
	return 0;
}