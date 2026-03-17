/// 
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.
/// 
/// \file   keygen.cpp
///
/// \brief  Generate a user's OpenABE ABE keys given function input.
///
/// \author J. Ayo Akinyele
///

#include "common_cli.h"
#include "../utils/utils.h"

using namespace std;

#define USAGE \
    "usage: [ -s scheme ] [ -p prefix ] [ -i input ] [ -o output ] -v\n\n" \
    "\t-v : turn on verbosity\n" \
    "\t-s : scheme types are 'PK', 'CP' or 'KP'\n" \
    "\t-i : key id for 'PK', attribute list for 'CP'/'MA' and policy string for 'KP'\n" \
    "\t-o : output file for generated secret key\n" \
        "\t-p : prefix for generated authority public and secret parameter files (optional)\n\n"

#if 0
int runPkeKeygen(string& id, string& suffix) {
  OpenABE_ERROR result = OpenABE_NOERROR;
  int err_code = -1;

  try {
    unique_ptr<OpenABEContextSchemePKE> schemeContext = OpenABE_createContextPKESchemeCCA(OpenABE_SCHEME_PK_OPDH);
    if (schemeContext == nullptr) {
        cerr << "unable to create a new context" << endl;
        return err_code;
    }

    // Generate a set of parameters for an ABE authority
    if ( (result = schemeContext->generateParams(DEFAULT_NIST_PARAM_STRING)) != OpenABE_NOERROR) {
        cerr << "Unable to generate curve parameters: " << DEFAULT_NIST_PARAM_STRING << endl;
        throw result;
    }

    // Compute party A's static public and private key
    const string keyId = "ID_" + id;
    const string pkId =  "public_" + id;
    const string skId = "private_" + id;
    if ((result = schemeContext->keygen(keyId, pkId, skId)) != OpenABE_NOERROR) {
        cerr << "unable to generate keys for: " << keyId << endl;
        throw result;
    }

    const string pubKeyFile = id + ".pk" + suffix;
    const string privKeyFile = id + ".sk" + suffix;
    OpenABEByteString publicKey, privateKey;
    schemeContext->exportKey(pkId, publicKey);
    schemeContext->exportKey(skId, privateKey);

    WriteToFile(pubKeyFile.c_str(), PK_BEGIN_HEADER + Base64Encode(publicKey.getInternalPtr(), publicKey.size()) + PK_END_HEADER);
    WriteToFile(privKeyFile.c_str(), SK_BEGIN_HEADER + Base64Encode(privateKey.getInternalPtr(), privateKey.size()) + SK_END_HEADER);
    err_code = 0;
  } catch (OpenABE_ERROR & error) {
    cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    err_code = error;
  }

  return err_code;
}
#endif

int runABEKeyGen(OpenABE_SCHEME scheme_type, string& prefix, string& suffix, string& keyInput, string& keyFile, string& userGlobID, bool verbose)
{
  int err_code = -1;
  OpenABE_ERROR result = OpenABE_NOERROR;
  std::unique_ptr<OpenABEContextSchemeCPA> schemeContext = nullptr;
  std::unique_ptr<OpenABEFunctionInput> funcInput = nullptr;
  OpenABEByteString mpkBlob, mskBlob, skBlob;

  string mpkID = MPK_ID, mskID = MSK_ID, skID = SK_ID, globSkID = userGlobID;
  string mpkFile = MPK_ID + suffix, mskFile = MSK_ID + suffix;
  if(prefix != "") {
    mpkFile = prefix + mpkFile;
    mskFile = prefix + mskFile;
  }

  // Initialize a OpenABEContext structure
  schemeContext = createContextABESchemeCPA(scheme_type);
  if (schemeContext == nullptr) {
    cerr << "unable to create a new context" << endl;
    return err_code;
  }

  try {
    // Get the functional input
    if(scheme_type == OpenABE_SCHEME_CP_WATERS) {
      funcInput = createAttributeList(keyInput);
			cout << "Je suis ici..." << endl;
    } else if(scheme_type == OpenABE_SCHEME_KP_GPSW) {
      funcInput = createPolicyTree(keyInput);
			cout << "Je suis là..." << endl;
    }
    ASSERT(funcInput != nullptr, OpenABE_ERROR_INVALID_INPUT);

    // Do it once for CP or KP
    // read the file
    mpkBlob = ReadFile(mpkFile.c_str());
    if (mpkBlob.size() == 0) {
        cerr << "master public parameters not encoded correctly." << endl;
        return err_code;
    }

    mskBlob = ReadFile(mskFile.c_str());
    if (mskBlob.size() == 0) {
        cerr << "master secret parameters not encoded correctly." << endl;
        return err_code;
    }

    if ((result = schemeContext->loadMasterPublicParams(mpkID, mpkBlob)) != OpenABE_NOERROR) {
        cerr << "unable to load the master public parameters" << endl;
        throw result;
    }

    if ((result = schemeContext->loadMasterSecretParams(mskID, mskBlob)) != OpenABE_NOERROR) {
        cerr << "unable to load the master secret parameters" << endl;
        throw result;
    }
    // generate the user's key
    if ((result = schemeContext->keygen(funcInput.get(), skID, mpkID, mskID)) != OpenABE_NOERROR) {
        cout << "decryption key error" << endl;
        throw result;
    }

     // export the generated key
     if ((result = schemeContext->exportKey(skID, skBlob)) != OpenABE_NOERROR) {
        cout << "unable to export master secret parameters" << endl;
        throw result;
     }

    WriteToFile(keyFile.c_str(), SK_BEGIN_HEADER + Base64Encode(skBlob.getInternalPtr(), skBlob.size()) + SK_END_HEADER);
    err_code = 0;
    } catch (OpenABE_ERROR & error) {
    	cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    	err_code = error;
    }

    return err_code;
}

int main(int argc, char **argv)
{
    if(argc <= 1) {
    cout << OpenABE_CLI_STRING << "keygen utility, v" << (OpenABE_LIBRARY_VERSION / 100.) << endl;
    fprintf(stderr, USAGE);
    exit(-1);
    }
    int opt, status = 0;
    string scheme_type = "", prefix = "", suffix = "", funcInputStr = "", keyOutfile = "";
    string userGlobID = "", keySuffix = KEY_SUFFIX;
    bool verbose = false;

    while ((opt = getopt(argc,argv,"p:s:i:o:v")) != EOF)
    {
    	switch(opt)
    	{
    		case 'p': prefix = string(optarg); break;
    		case 's': scheme_type = string(optarg); break;
    		case 'i': funcInputStr = string(optarg); break;
    		case 'o': keyOutfile = optarg; break;
    		case 'v': verbose = true; break;
    		case '?': fprintf(stderr, USAGE);
    		default: cout << endl; exit(-1);
    	}
    }
    // check prefix ending
    addNameSeparator(prefix);
    // validate scheme type
    OpenABE_SCHEME scheme = checkForScheme(scheme_type, suffix);
    if(scheme == OpenABE_SCHEME_NONE) {
        cerr << "selected an invalid scheme type. Try again with -s option.\n";
    	return -1;
    }

    addFileExtension(keyOutfile, keySuffix);

    InitializeOpenABE();

  if (scheme == OpenABE_SCHEME_PK_OPDH) {
    string key_id = funcInputStr;
    if (key_id == "") {
        cerr << "missing user's key ID. Specify with -i option." << endl;
        status = -1;
        goto cleanup;
    }
    // runPkeKeygen(key_id, suffix);
    cout << "------------> Je suis en maintenance, je reviendrai plus fort." << endl;
  } else {
    cout << "functional key input: "<< funcInputStr << endl;
    status = runABEKeyGen(scheme, prefix, suffix, funcInputStr, keyOutfile, userGlobID, verbose);
  }

cleanup:

  ShutdownOpenABE();

  return status;
}
