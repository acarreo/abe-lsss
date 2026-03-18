/// 
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.
/// 
/// \file   decrypt.cpp
///
/// \brief  OpenABE decryption utility
///
/// \author J. Ayo Akinyele
///

#include "common_cli.h"
#include "../utils/utils.h"

using namespace std;

#define USAGE \
    "usage: [ -s scheme ] [ -p prefix ] [ -k key ] [ -i ciphertext ] [ -o output ] -v\n\n" \
    "\t-v : turn on verbosity\n" \
    "\t-s : scheme types are 'PK', 'CP' or 'KP'\n" \
    "\t-k : recipient key Id for 'PK' and secret key file for 'CP'/'KP'\n" \
    "\t-e : sender key Id for 'PK'\n" \
    "\t-i : ciphertext file \n" \
    "\t-o : output file for plaintext\n" \
    "\t-p : prefix for generated authority public and secret parameter files (optional)\n\n" \

#if 0
int runPKDecrypt(string& suffix, string& sender_id, string& recipient_id,
                  string& ciphertext_file, string& decrypted_file, bool verbose) {
    OpenABE_ERROR result = OpenABE_NOERROR;
    int err_code = 0;
    // load public key file for the recipient
    OpenABEByteString send_PublicKey, recp_PrivateKey, ctBlob;
    string plaintext;
    try {
        if (!getPublicKey(send_PublicKey, sender_id, suffix)) {
            cerr << "unable to load the public key: " << sender_id << endl;
            return -1;
        }
        if (!getPrivateKey(recp_PrivateKey, recipient_id, suffix)) {
            cerr << "unable to load the private key: " << recipient_id << endl;
            return -1;
        }

        ctBlob = ReadBlockFromFile(CT2_BEGIN_HEADER, CT2_END_HEADER, ciphertext_file.c_str());
        if (ctBlob.size() == 0) {
            cerr << "ciphertext not encoded properly." << endl;
            return -1;
        }

        unique_ptr<OpenABEContextSchemePKE> schemeContext = OpenABE_createContextPKESchemeCCA(OpenABE_SCHEME_PK_OPDH);
        if (schemeContext == nullptr) {
            cerr << "unable to create a new context" << endl;
            return -1;
        }

        // Generate a set of parameters for an ABE authority
        if ( (result = schemeContext->generateParams(DEFAULT_NIST_PARAM_STRING)) != OpenABE_NOERROR) {
            cerr << "unable to generate curve parameters: " << DEFAULT_NIST_PARAM_STRING << endl;
            throw result;
        }

        string sen_pkID = "public_" + sender_id;
        string rec_skID = "private_" + recipient_id;
        if ((result = schemeContext->loadPublicKey(sen_pkID, send_PublicKey)) != OpenABE_NOERROR) {
            cerr << "unable to load the sender's public key: " << sen_pkID << endl;
            throw result;
        }

        if ((result = schemeContext->loadPrivateKey(rec_skID, recp_PrivateKey)) != OpenABE_NOERROR) {
            cerr << "unable to load the recipient's private key: " << rec_skID << endl;
            throw result;
        }

        unique_ptr<OpenABECiphertext> ciphertext(new OpenABECiphertext);
        ciphertext->loadFromBytes(ctBlob);
        if ((result = schemeContext->decrypt(sen_pkID, rec_skID, plaintext, ciphertext.get())) != OpenABE_NOERROR) {
            cerr << "error while decrypting PK-encrypted object: " << ciphertext_file << endl;
            throw result;
        }

        err_code = 0;
        if(verbose) {
            cout << "writing " << plaintext.size() << " bytes to " << decrypted_file << endl;
        }
        WriteBinaryFile(decrypted_file.c_str(), (uint8_t *) plaintext.c_str(), plaintext.size());

    } catch (OpenABE_ERROR & error) {
        cout << "caught exception: " << OpenABE_errorToString(error) << endl;
        err_code = error;
    }

    return err_code;
}
#endif


int runABEDecrypt(OpenABE_SCHEME scheme_type, string& prefix, string& suffix,
    	       string& skFile, string& ciphertext_file, string& decrypted_file, bool verbose)
{
  OpenABE_ERROR result = OpenABE_NOERROR;
  std::unique_ptr<OpenABEContextSchemeCPA> schemeContext = nullptr;
  OpenABECiphertext ciphertext;

  int err_code = 0;
  string mpkID = MPK_ID, skID = skFile;
  string mpkFile = MPK_ID + suffix;
  if(prefix != "") {
    mpkFile = prefix + mpkFile;
  }

  // read the file
  OpenABEByteString mpkBlob, skBlob, ctBlob;
  OpenABEByteString decrypted;

  try {
    // Initialize a OpenABEContext structure
    schemeContext = createContextABESchemeCPA(scheme_type);
    if (schemeContext == nullptr) {
      cerr << "unable to create a new context" << endl;
      return -1;
    }

    // load KP/CP public params
    mpkBlob = ReadFile(mpkFile.c_str());
    if (mpkBlob.size() == 0) {
      cerr << "master public parameters not encoded properly." << endl;
      return -1;
    }
    
    if ((result = schemeContext->loadMasterPublicParams(mpkID, mpkBlob)) != OpenABE_NOERROR) {
      cerr << "unable to load the master public parameters" << endl;
      throw result;
    }

    skBlob = ReadFile(skFile.c_str());
    if (skBlob.size() == 0) {
      cerr << "secret key not encoded properly." << endl;
      return -1;
    }

    ctBlob = ReadBlockFromFile(CT1_BEGIN_HEADER, CT1_END_HEADER, ciphertext_file.c_str());
    if (ctBlob.size() == 0) {
      cerr << "ABE ciphertext not encoded properly." << endl;
      return -1;
    }

    // Load the ciphertext components
    ciphertext.loadFromBytes(ctBlob);

    if (verbose) {
      cout << "read " << ctBlob.size() << " bytes" << endl;
    }
  } catch (OpenABE_ERROR& error) {
    cout << "caught exception: " << OpenABE_errorToString(error) << endl;
    return error;
  }

    try {
        // now we can load the user's secret key
        if ((result = schemeContext->loadUserSecretParams(skID, skBlob)) != OpenABE_NOERROR) {
          cerr << "Unable to load user's decryption key" << endl;
          throw result;
        }

        // now we can decrypt
        if ((result = schemeContext->decrypt(mpkID, skID, decrypted, ciphertext)) != OpenABE_NOERROR) {
          throw result;
        }

        err_code = 0;
        if(verbose) {
          cout << "writing " << decrypted.size() << " bytes to " << decrypted_file << endl;
        }
        WriteBinaryFile(decrypted_file, decrypted);
    } catch (OpenABE_ERROR & error) {
        cout << "caught exception: " << OpenABE_errorToString(error) << endl;
        err_code = error;
    }

    return err_code;
}

int main(int argc, char **argv)
{
  if(argc <= 1) {
    cout << OpenABE_CLI_STRING << "decryption utility, v" << (OpenABE_LIBRARY_VERSION / 100.) << endl;
    fprintf(stderr, USAGE);
    exit(-1);
  }
  int opt;
  string scheme_name, prefix, suffix;
  string mpk_file, sender_id, recipient_id, key_file, ciphertext_file, out_file;
  bool verbose = false;
  while ((opt = getopt(argc,argv,"e:k:p:s:i:o:r:v")) != EOF)
  {
    switch(opt)
    {
      case 'e': sender_id = string(optarg); break;
      case 's': scheme_name = string(optarg); break;
      case 'p': prefix = string(optarg); break;
      case 'k': key_file = string(optarg); break;
      case 'i': cout << "ciphertext: "<< optarg << endl; ciphertext_file = optarg; break;
      case 'r': recipient_id = string(optarg); break;
      case 'o': out_file = optarg; break;
      case 'v': verbose = true; break;
      case '?': fprintf(stderr, USAGE);
      default: cout<<endl; exit(-1);
    }
  }

    // check prefix ending
    addNameSeparator(prefix);
    // validate scheme type
    OpenABE_SCHEME scheme_type = checkForScheme(scheme_name, suffix);
    if (scheme_type == OpenABE_SCHEME_NONE) {
    	cerr << "selected an invalid scheme type. Try again with -s option.\n";
    	return -1;
    }

    if (ciphertext_file == "") {
        cerr << "please specify a ciphertext file with -i option." << endl;
    }

    if (out_file == "") {
    	cerr << "please specify an output file with -o option." << endl;
    	return -1;
    }

    InitializeOpenABE();

  int err_code = 0;
  if (scheme_type == OpenABE_SCHEME_PK_OPDH) {
    if (sender_id == "" || recipient_id == "") {
      cerr << "missing sender ID (-e option) and/or recipient ID (-r option)" << endl;
      goto cleanup;
    }
    // err_code = runPKDecrypt(suffix, sender_id, recipient_id, ciphertext_file, out_file, verbose);
    cout << "------------> Je suis en maintenance, je reviendrai plus fort." << endl;
  } else {
    cout << "user's SK file: " << key_file << endl;
    err_code = runABEDecrypt(scheme_type, prefix, suffix, key_file, ciphertext_file, out_file, verbose);
  }

cleanup:
  ShutdownOpenABE();

  return err_code;
}
