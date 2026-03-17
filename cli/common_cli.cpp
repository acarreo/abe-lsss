/// 
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.
///
/// \file   common.cpp
///
/// \brief  Common routines and shared functionality
///
/// \author J. Ayo Akinyele
///

#include <filesystem>
#include "common_cli.h"

using namespace std;

void getFile(std::string &result, const std::string &filename) {
  result.clear();

  fstream fs(filename, fstream::in);
  if (fs.fail()) {
    string msg = "Could not open file ";
    msg += filename;
    throw ios_base::failure(msg);
  }

  fs.exceptions(fstream::badbit);
  while (!fs.eof()) {
    char buf[512];
    fs.read(buf, sizeof(buf));
    result.append(buf, fs.gcount());
  }

  fs.close();
}


OpenABE_SCHEME checkForScheme(string type, string &suffix)
{
    suffix.clear();
    if(type == CP_ABE) {
    	suffix = ".cpabe";
    	return OpenABE_SCHEME_CP_WATERS;
    } else if(type == KP_ABE) {
    	suffix = ".kpabe";
    	return OpenABE_SCHEME_KP_GPSW;
    } else if(type == PK_ENC) {
        suffix = ".pkenc";
        return OpenABE_SCHEME_PK_OPDH;
    } else {
    	return OpenABE_SCHEME_NONE;
    }
}

void addNameSeparator(string &prefix)
{
    // check if last character of prefix is a name separator (if not, add it)
    if(prefix.size() > 0 && prefix[prefix.size()-1] != NAME_SEP) {
    	prefix += NAME_SEP;
    }
}

// adds an extension if not present
void addFileExtension(string &filename, string ext)
{
    if(filename.find(ext) == string::npos) {
    	filename += ext;
    }
}

void WriteToFile(const char* filename, string outputStr)
{
    ofstream file;
    file.open(filename);
    file << outputStr;
    file.close();
}

string ReadFile(const char* filename)
{
    ifstream input(filename);
    string line = "";
    // read everthing between the headers
    if (input.is_open()) {
			cout << "JE suis quelque part dans ReadFile" << endl;
    	while(getline(input, line)) {
    		/* finish this
    		if(line.compare(begin_header) == 0)
    		   continue;
    		*/
    		if(line.find(BLOCK) == std::string::npos) {
    			break;
    		}
    	}
    	input.close();
    }

    return Base64Decode(line);
}

string ReadBlockFromFile(const char* begin_header, const char* end_header, const char* filename)
{
    ifstream input(filename);
    string block = "", line;
    bool found_header = false;
    // read everthing between the headers
    if(input.is_open()) {
    	while(getline(input, line)) {
    		if(line.compare(begin_header) == 0) {
    		   found_header = true;
    			continue;
    		}
    		else if(line.compare(end_header) == 0) {
    			break;
    		}
    		if(found_header) block = line;
    	}
    	input.close();
    }

    return Base64Decode(block);
}

void WriteBinaryFile(const char* filename, string& outputStr)
{
    ofstream file;
    file.open(filename, ios::out | ios::binary);
    file << outputStr;
    file.close();
}

void WriteBinaryFile(const char* filename, uint8_t *buf, uint32_t len)
{
    ofstream file;
    file.open(filename, ios::out | ios::binary);
    // file << outputStr;
    file.write((const char *) buf, (int) len);
    file.close();
}

string ReadBinaryFile(const char* filename)
{
    ifstream input(filename, ios::binary);
    string inputBlob = "", line;
    // read everthing between the headers
    if(input.is_open()) {
    	while(getline(input, line)) {
    		inputBlob += line + "\n";
    	}
    	input.close();
    }

    return inputBlob;
}


//
// The following functions come from
// https://github.com/acarreo/secure-file-transfer/blob/main/src/protocol/user.cpp
//

bool readBytesFromFile(const std::string &filename, OpenABEByteString &buff) {
  std::ifstream file(filename, std::ios::binary | std::ios::ate);
  if (!file) {
    std::cerr << "ERROR --> Could not open file: " << filename << std::endl;
    return false;
  }

	std::uintmax_t f_size = std::filesystem::file_size(filename);
	if (f_size > std::numeric_limits<size_t>::max()) {
		throw std::runtime_error("File too large");
	}
	size_t size = static_cast<size_t>(f_size);

  buff.clear();
  buff.fillBuffer(0, size);
  file.read(reinterpret_cast<char *>(buff.getInternalPtr()),
            static_cast<std::streamsize>(size));
  bool err = file.good();
  if (err == false) {
    std::cerr << "ERROR --> Could not read file: " << filename << std::endl;
  }

  file.close();
  return err;
}

void writeBytesToFile(const std::string &filename,
                      const OpenABEByteString &buff) {
  std::ofstream file(filename, std::ios::binary);
  file.write(reinterpret_cast<const char *>(buff.data()),
             static_cast<std::streamsize>(buff.size()));
  file.close();
}

int __create_directory(const std::string &path) {
  try {
    std::filesystem::path dir(path);
    if (std::filesystem::exists(dir)) {
      if (!std::filesystem::is_directory(dir)) {
        std::cerr << "ERROR --> Path exists but is not a directory: " << path
                  << std::endl;
        return 1; // Path exists but is not a directory
      }
    } else {
      if (!std::filesystem::create_directory(dir)) {
        std::cerr << "ERROR --> Failed to create directory: " << path
                  << std::endl;
        return 2; // Failed to create directory
      }
    }
  } catch (const std::filesystem::filesystem_error &e) {
    std::cerr << __func__ << " ---> ERROR: " << e.what() << std::endl;
    return -1; // Handle filesystem error
  }
  return 0;
}

