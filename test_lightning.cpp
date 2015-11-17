#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "snarkfront.hpp"

using namespace snarkfront;
using namespace cryptl;
using namespace std;

void printUsage(const char* exeName) {
    cout << "usage: " << exeName
         << " -m keygen|input|proof|verify"
         << " -s secret"
         << " -h hash-of-secret"
         << " -b hash-of-secret_xor_delta"
         << " -x delta"
         << endl;

    exit(EXIT_FAILURE);
}

#if (CHAR_BIT != 8)
#error "large chars confuses me (CHAR_BIT != 8)"
#endif

template<typename T>
typename T::DigType do_digest(
        T hashAlgo,
        std::size_t n,
        const vector<uint8_t> &data,
        vector<typename T::WordType> &blessdata)
{
    typename T::MsgType msg; // 512 bit block as array of 16 uint32_t's, except snarked
    typename T::WordType::ValueType msg_int; // uint32_t

    assert(n % sizeof(msg_int) == 0);
    assert(n < msg.size() * sizeof(msg_int)); // n+padding actually has to equal this
    assert(blessdata.size() == 0);

    stringstream ss;
    std::size_t i = 0;
    for (const auto& c : data) {
        ss.put(c);
        i++;
    }
    while (i++ < n) {
        ss.put('\0');
    }

    bool padded = false;
    for (auto &m : msg) {
        if (!bless(msg_int, ss)) {
            if (!padded && ss.eof()) {
                std::size_t lengthBits = n * CHAR_BIT;
                ss.clear();
                T::padMessage(ss, lengthBits);
                assert(lengthBits == msg.size() * sizeof(msg_int) * CHAR_BIT);
                assert(!ss.eof());
                padded = true;
            }
            if (!bless(msg_int, ss)) {
                assert(padded); // should be padded by now
                assert(false); // ran out of input -- padding didn't work
                msg_int = ~0;
            }
        }
        bless(m, msg_int);

        // ensure proof validates correct padding
        if (padded)
            assert_true(m == msg_int);
        else
            blessdata.push_back(m);
    }

    hashAlgo.msgInput(msg);
    hashAlgo.computeHash();
    return hashAlgo.digest();
}

typedef BN128_FR FR;
typedef BN128_PAIRING PAIRING;

template <typename HC, typename HS, std::size_t N>
struct Algo {
    // secret/witness
    vector<uint8_t> preImageFwd;    // digest() only works on vectors
    vector<uint8_t> preImageBck;

    // actual input data (hash and xor)
    typename HC::DigType pubHashFwd;
    typename HC::DigType pubHashBck;
    array<typename HC::WordType, N/sizeof(typename HC::WordType)> pubXor;

    // pub input for circuit (hash and xor)
    typename HS::DigType pubVarsFwd;
    typename HS::DigType pubVarsBck;
    array<typename HS::WordType, N/sizeof(typename HC::WordType)> pubVarsXor;

    GenericProgressBar progress;

    static bool asc2hash(const std::string hash, typename HC::DigType &chkHash)
    {
        vector<uint8_t> v;
        const size_t digbytes = sizeof(typename HC::DigType);
        if (!asciiHexToVector(hash, v) || v.size() != digbytes)
            return false;

        stringstream ss;
        for (const auto& c : v)
                ss.put(c);
        for (auto& i : chkHash)
                bless(i, ss);
        return true;
    }

    void _init_pubXor(const vector<uint8_t> &PreXor) {
        stringstream ss;
        std::size_t i = 0;
        for (const auto &c : PreXor) {
            ss.put(c);
            i++;
        }
        while (i++ < N)
            ss.put('\0');
        for (auto &w : pubXor) {
            bless(w, ss);
        }
    }

    Algo(const vector<uint8_t> &PreXor, const std::string secret)
      : progress(cerr, 50)
    {
        auto xi = PreXor.begin();
        uint8_t x;
        for (const auto& c : secret) {
            x = (xi == PreXor.end() ? 0 : *(xi++));
            preImageFwd.push_back(c);
            preImageBck.push_back(c ^ x);
        }
        assert(preImageFwd.size() <= N);
        while(preImageFwd.size() < N) {
            x = (xi == PreXor.end() ? 0 : *(xi++));
            preImageFwd.push_back('\0');
            preImageBck.push_back(x);
        }
        assert(xi == PreXor.end());
        assert(preImageFwd.size() == N);
        assert(preImageBck.size() == N);

        _init_pubXor(PreXor);
        pubHashFwd = digest(HC(), preImageFwd);
        pubHashBck = digest(HC(), preImageBck);
    }

    Algo(vector<uint8_t> &PreXor,
         typename HC::DigType &chkHashFwd,
         typename HC::DigType &chkHashBck)
      : progress(cerr, 50)
    {
        _init_pubXor(PreXor);
        pubHashFwd = chkHashFwd;
        pubHashBck = chkHashBck;
    }

    void _input_step() {
        bless(pubVarsXor, pubXor);
        bless(pubVarsFwd, pubHashFwd);
        bless(pubVarsBck, pubHashBck);
        end_input<PAIRING>();
    }
    void _calc_step() {
        vector<typename HS::WordType> blessFwd, blessBck;
        assert_true(pubVarsFwd == do_digest(HS(), N, preImageFwd, blessFwd));
        assert_true(pubVarsBck == do_digest(HS(), N, preImageBck, blessBck));

        assert(blessFwd.size() == blessBck.size());
        assert(blessFwd.size() == pubXor.size());
        for (std::size_t i = 0; i < blessFwd.size(); i++) {
            assert_true(blessFwd[i] == (blessBck[i] ^ pubVarsXor[i]));
        }
    }

    void do_keygen(void) {
        // trusted key generation

        _input_step();
        _calc_step();

        // generate proving/verification key pair
        cerr << "generate key pair";
        cout << keypair<PAIRING>(progress); // expensive!
        cerr << endl;
    }

    void do_input(void) {
        _input_step();
        // publicly known input variables
        cout << input<PAIRING>();
    }

    void do_proof(Keypair<PAIRING> &keypair) {
        // generate a proof

        // check for marshalling errors
        assert(!keypair.empty());

        _input_step();
        _calc_step();

        // generate proof
        cerr << "generate proof";
        cout << proof(keypair, progress);
        cerr << endl;
    }

    void do_verify(Keypair<PAIRING> &keypair, Proof<PAIRING> &proof) {
        _input_step();
        Input<PAIRING> inp = input<PAIRING>();

        // check for marshalling errors
        assert(!keypair.empty() && !proof.empty());

        // verify proof
        cerr << "verify proof ";
        const bool valid = verify(keypair, inp, proof, progress);
        cerr << endl;
        cout << "proof is " << (valid ? "verified" : "rejected") << endl;
    }
};

int main(int argc, char *argv[])
{
    const std::size_t hashbytes = 32;
    Getopt cmdLine(argc, argv, "mshbx", "", "");
    if (!cmdLine || cmdLine.empty()) printUsage(argv[0]);

    const auto mode = cmdLine.getString('m');
    const auto prefwd = cmdLine.getString('s');
    const auto hashfwd = cmdLine.getString('h');
    const auto hashbck = cmdLine.getString('b');
    const auto prexor = cmdLine.getString('x');

    typedef Algo<cryptl::SHA256,snarkfront::SHA256<FR>, hashbytes> SHA256Algo;

    cryptl::SHA256::DigType chkHashFwd, chkHashBck;
    vector<uint8_t> PreXor;
    SHA256Algo *algo;

    cerr << "m: " << mode << "." << endl;
    cerr << "f: " << hashfwd << "." << endl;
    cerr << "b: " << hashbck << "." << endl;
    cerr << "x: " << prexor << "." << endl;

    if (mode != "keygen") {
        if (prexor == "") {
            cerr << "Must supply xor" << endl;
            return 1;
        }
        if (prefwd == "" && (hashfwd == "" || hashbck == "")) {
            cerr << "Must supply hashes or preimage" << endl;
            return 1;
        }

        if (!asciiHexToVector(prexor, PreXor) || PreXor.size() == 0) {
            cerr << "Invalid xor string: " << prexor << "." << endl;
            return 1;
        }
        if (PreXor.size() > hashbytes) {
            cerr << "Xor string is too long (max " << hashbytes << "bytes)" << endl;
            return 1;
        }
        if (prefwd.size() > hashbytes) {
            cerr << "preimage is too long (max " << hashbytes << " bytes)" << endl;
            return 1;
        }

        if (hashfwd != "") {
            if (!SHA256Algo::asc2hash(hashfwd, chkHashFwd)) {
                cerr << "Invalid hash string: " << hashfwd << "." << endl;
                return 1;
            }
        }
        if (hashbck != "") {
            if (!SHA256Algo::asc2hash(hashbck, chkHashBck)) {
                cerr << "Invalid hash string: " << hashbck << "." << endl;
                return 1;
            }
        }
    }

    // Barreto-Naehrig 128 bits
    init_BN128();

    if (prefwd == "") {
        algo = new SHA256Algo(PreXor, chkHashFwd, chkHashBck);
    } else {
        algo = new SHA256Algo(PreXor, prefwd);
        cerr << "F: " << asciiHex(algo->preImageFwd) << endl;
        cerr << "B: " << asciiHex(algo->preImageBck) << endl;
        cerr << "#F: " << asciiHex(algo->pubHashFwd) << endl;
        cerr << "#B: " << asciiHex(algo->pubHashBck) << endl;
        if (hashfwd != "") {
            if (chkHashFwd != algo->pubHashFwd) {
                cerr << "Supplied forward hash does not match preimage hash" << endl;
                return 1;
            }
        }
        if (hashbck != "") {
            if (chkHashBck != algo->pubHashBck) {
                cerr << "Supplied backward hash does not match calculated preimage hash" << endl;
                return 1;
            }
        }
    }

    if ("keygen" == mode) {
        algo->do_keygen();
    } else if ("input" == mode) {
        algo->do_input();
    } else if ("proof" == mode) {
        Keypair<PAIRING> keypair; // proving/verification key pair
        cin >> keypair;
        algo->do_proof(keypair);
    } else if ("verify" == mode) {
        // verify a proof
        Keypair<PAIRING> keypair; // proving/verification key pair
        Proof<PAIRING> proof;     // zero knowledge proof

        cin >> keypair >> proof;

        algo->do_verify(keypair, proof);
    } else {
        // no mode specified
        printUsage(argv[0]);
    }

    return EXIT_SUCCESS;
}
