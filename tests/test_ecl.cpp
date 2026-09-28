#include <ecl/ecl.hpp>
#include "internal.hpp"
#include <algorithm>
#include <chrono>
#include <functional>
#include <iostream>
#include <map>
#include <numeric>
#include <random>

namespace {
using namespace ecl;
#define CHECK(condition) do { if (!(condition)) throw std::runtime_error(std::string("check failed: ") + #condition + " at line " + std::to_string(__LINE__)); } while (false)
template<class F> void fails(F&& function) {
    bool failed = false;
    try { function(); } catch (const Error&) { failed = true; }
    CHECK(failed);
}
Bytes sequence(std::size_t n, unsigned start = 0) {
    Bytes data(n);
    for (std::size_t i = 0; i < n; ++i) data[i] = static_cast<Byte>(i + start);
    return data;
}
const auto key = sequence(32);
const auto nonce = sequence(32, 32);
Bytes pe() {
    Bytes p(4096);
    const auto put = [&](std::size_t off, std::uint32_t value, int width) {
        for (int i = 0; i < width; ++i) p[off + static_cast<std::size_t>(i)] = static_cast<Byte>(value >> (8 * i));
    };
    p[0]='M'; p[1]='Z'; put(0x3c,128,4); p[128]='P'; p[129]='E';
    put(132,0x8664,2); put(134,1,2); put(148,240,2); put(150,0x22,2); put(152,0x20b,2);
    const std::string name=".text"; std::copy(name.begin(),name.end(),p.begin()+392);
    put(400,3584,4); put(404,4096,4); put(408,3584,4); put(412,512,4);
    for (std::size_t i=512;i<p.size();++i) p[i]=static_cast<Byte>(i);
    return p;
}
void exhaustive() {
    std::size_t cases=0;
    for (std::size_t n=0;n<=6;++n) {
        std::map<Counts,std::size_t> seen;
        std::size_t limit=1; for(std::size_t i=0;i<n;++i) limit*=3;
        for(std::size_t ordinal=0;ordinal<limit;++ordinal) {
            Bytes p(n); auto value=ordinal;
            for(auto i=n;i>0;--i) {p[i-1]=static_cast<Byte>(value%3);value/=3;}
            const auto h=histogram(p); auto& expected=seen[h];
            CHECK(rank_bytes(p,h)==expected); CHECK(unrank_bytes(expected,h)==p);
            ++expected; ++cases;
        }
        for(const auto& [h,count]:seen) CHECK(multinomial(h)==count);
    }
    CHECK(cases==1093);
}
void random_enumeration() {
    std::mt19937 rng(270928);
    for(int i=0;i<80;++i) {
        const std::array<unsigned,4> alphabets{1,2,7,256};
        Bytes p(rng()%600); const auto alphabet=alphabets[rng()%4];
        for(auto& b:p) b=static_cast<Byte>(rng()%alphabet);
        const auto h=histogram(p); CHECK(unrank_bytes(rank_bytes(p,h),h)==p);
    }
}
void invalid_ranks() {
    auto h=histogram(Bytes{'A','A','B'});
    for(int r:{-1,3,100}) fails([&]{unrank_bytes(r,h);});
    fails([&]{rank_bytes(Bytes{'A','A','A'},h);});
    fails([&]{rank_bytes(Bytes{'A'},h);});
    fails([&]{rank_length(0);});
    Counts huge{};huge[0]=UINT64_MAX;huge[1]=1;
    fails([&]{multinomial(huge);});
}
void spills() {
    for(unsigned m=1;m<=1024;++m) {
        const auto width=rank_length(m);
        const BigInt largest=(BigInt(1)<<(8*width))-1;
        for(const BigInt& x:std::vector<BigInt>{0,m-1,m,largest}) {
            if(x>largest) continue;
            CHECK(x/m<=255); CHECK((x/m)*m+x%m==x);
            CHECK(detail::to_int(detail::from_int(x,width))==x);
        }
    }
}
void policies() {
    std::vector<Bytes> samples{Bytes(4096),sequence(4096),Bytes(4096,'A'),sequence(97)};
    std::fill(samples[2].begin()+2500,samples[2].begin()+3700,'B');
    std::fill(samples[2].begin()+3700,samples[2].end(),'C');
    for(const auto& p:samples) {
        const auto h=histogram(p); double last=0;
        for(const auto* value:{"0","0.001","0.05","0.1","0.25","0.5","1","8"}) {
            const auto b=budget_units(value);const auto q=shape_counts(h,b);
            CHECK(std::accumulate(q.begin(),q.end(),std::uint64_t(0))==p.size());
            CHECK(multinomial(q)>=multinomial(h));verify_entropy_policy(h,q,1,b);
            CHECK(entropy(q)+1e-12>=last);last=entropy(q);
        }
    }
}
void exact_policy() {
    Counts h{};h[0]=6;h[1]=3;h[2]=1;Counts q{};q[255]=18;q[254]=9;q[253]=3;
    CHECK(normalized_profile(h)==normalized_profile(q));verify_entropy_policy(h,q,2,0);
    q[255]--;q[254]++;fails([&]{verify_entropy_policy(h,q,2,0);});
    fails([&]{verify_entropy_policy(h,q,1,0);});
}
void budgets() {
    for(const auto* b:{"nan","NaN","inf","-0.1","8.1","0.0000000000001","abc","1e","1e999999","1e-13","1e2","1.2.3"})
        fails([&]{budget_units(b);});
    CHECK(budget_units("0.000000000001")==1);
    CHECK(budget_units("8.0000000000000")==8*scale);
    CHECK(budget_units("+2.50e-1")==scale/4);
    CHECK(budget_units("-0")==0);
    Options options;options.budget="0.1";fails([&]{encrypt(sequence(3),key,options);});
    options.budget="0";options.profile=0;fails([&]{encrypt(sequence(3),key,options);});
    options.profile=2;options.layout=static_cast<Layout>(3);fails([&]{encrypt(sequence(3),key,options);});
}
void pe_validation() {
    CHECK(check_pe(pe())["format"]=="PE32+");
    for(const auto& p:std::vector<Bytes>{Bytes{'M','Z'},Bytes(1000),Bytes(4096)}) fails([&]{check_pe(p);});
    auto p=pe();p[152]=0x0b;p[153]=1;CHECK(check_pe(p)["format"]=="PE32");
    for(auto offset:{0U,0x3cU,128U,134U,148U,152U,411U}) {
        auto broken=pe();broken[offset]^=0xff;fails([&]{check_pe(broken);});
    }
}
void resources() {
    Options options;options.max_plain=99;fails([&]{encrypt(Bytes(100),key,options);});
    options.max_plain=256;options.max_cipher=300;options.layout=Layout::embedded;
    fails([&]{encrypt(sequence(256),key,options);});
    fails([&]{decrypt(Bytes(100),key,std::nullopt,256,99);});
    fails([&]{encrypt(sequence(10),Bytes(31));});
    fails([&]{decrypt(sequence(10),Bytes(33));});
    auto encrypted=encrypt(sequence(256),key);
    fails([&]{decrypt(encrypted.ciphertext,key,encrypted.sidecar,255);});
}
void zero_capacity() {
    Options options;options.layout=Layout::embedded;
    for(const auto& p:std::vector<Bytes>{Bytes{},Bytes{'A'},Bytes(2048,'A')}) fails([&]{encrypt(p,key,options);});
}
void all_profiles_layouts() {
    const auto p=pe();
    for(int profile=1;profile<=2;++profile) for(auto layout:{Layout::detached,Layout::embedded}) {
        Options options;options.profile=profile;options.layout=layout;options.budget=profile==2?"0":"0.25";
        const auto c=encrypt(p,key,options);const auto d=decrypt(c.ciphertext,key,c.sidecar);
        CHECK(d.plaintext==p);CHECK(c.report["cipher_sha256"]==d.report["cipher_sha256"]);
        verify_entropy_policy(histogram(p),histogram(c.ciphertext),profile,budget_units(options.budget));
        if(layout==Layout::detached) {CHECK(c.ciphertext.size()==p.size());CHECK(c.sidecar->size()==2213);}
        else {CHECK(!c.sidecar);CHECK(c.ciphertext.size()%p.size()==0);}
    }
}
void random_roundtrips() {
    std::mt19937 rng(19870419);
    for(auto n:{0,1,2,3,16,31,128,255,256,257,1024}) for(int profile:{1,2}) {
        Bytes p(static_cast<std::size_t>(n));for(auto& b:p)b=static_cast<Byte>(rng());
        Options options;options.profile=profile;options.budget=profile==1?"0.1":"0";
        const auto c=encrypt(p,key,options);CHECK(c.ciphertext.size()==p.size());CHECK(decrypt(c.ciphertext,key,c.sidecar).plaintext==p);
    }
}
void constant_inputs() {
    for(int symbol:{0,1,127,255}) {
        const Bytes p(1024,static_cast<Byte>(symbol));const auto c=encrypt(p,key);
        CHECK(entropy(histogram(c.ciphertext))==0);CHECK(decrypt(c.ciphertext,key,c.sidecar).plaintext==p);
    }
    Options options;options.profile=1;options.budget="1";options.layout=Layout::embedded;
    const auto c=encrypt(Bytes(4096),key,options);CHECK(decrypt(c.ciphertext,key,c.sidecar).plaintext==Bytes(4096));
}
void nonce_freshness() {
    const auto a=encrypt(sequence(1024),key),b=encrypt(sequence(1024),key);
    CHECK(a.ciphertext!=b.ciphertext);CHECK(a.sidecar!=b.sidecar);
    CHECK(!std::equal(a.sidecar->begin()+36,a.sidecar->begin()+68,b.sidecar->begin()+36));
}
void regression_vectors() {
    const std::array<const char*,4> hashes{
        "3e592c9dd4d0a63253374103e254e6cf4605c26cda1226fa8a44e573f7c8e29c",
        "7b6e62258fe29b8c003aae4fb5c53469de16e5b93fcdd28a1dd3543e58a835de",
        "2887f945b90fdf3b2b33502a6d737d84dd01cf41658827999b73b521e0ed373f",
        "cf7388de66b78731f23a9cfcfcfeaa10a7caf3e5d2700a27e78213fa9e34f25d"};
    const std::array<const char*,2> metas{
        "3e7ca8a64b43ea548342a9a00c247975ba2088a66e0b87b9827e5602f055d93e",
        "7b2b35dab6d6156420e553e7e9447ee3ecf3ce3962b9c9d9f1fa940b9b2ed87d"};
    std::size_t index=0;
    for(int profile:{1,2}) for(auto layout:{Layout::detached,Layout::embedded}) {
        Options options;options.profile=profile;options.layout=layout;options.budget=profile==1?"0.25":"0";
        const auto c=detail::encrypt_with_nonce(sequence(1024),key,options,nonce);
        CHECK(hex(sha256(c.ciphertext))==hashes[index++]);
        if(c.sidecar) CHECK(hex(sha256(*c.sidecar))==metas[static_cast<std::size_t>(profile-1)]);
        CHECK(decrypt(c.ciphertext,key,c.sidecar).plaintext==sequence(1024));
    }
}
void wrong_keys() {
    for(auto layout:{Layout::detached,Layout::embedded}) {
        Options options;options.layout=layout;const auto c=encrypt(sequence(1024),key,options);
        bool authentication=false;
        try{decrypt(c.ciphertext,Bytes(32),c.sidecar);}catch(const AuthenticationError&){authentication=true;}
        CHECK(authentication);
    }
}
void tamper() {
    const auto c=encrypt(sequence(1024),key);
    for(auto i:{0U,512U,1023U}) {auto bad=c.ciphertext;bad[i]^=1;fails([&]{decrypt(bad,key,c.sidecar);});}
    for(auto i:{0U,8U,9U,10U,11U,12U,20U,28U,36U,68U,99U,100U,1106U,2212U}) {
        auto bad=*c.sidecar;bad[i]^=1;fails([&]{decrypt(c.ciphertext,key,bad);});
    }
    auto shortened=c.ciphertext;shortened.pop_back();fails([&]{decrypt(shortened,key,c.sidecar);});
    auto meta=*c.sidecar;meta.pop_back();fails([&]{decrypt(c.ciphertext,key,meta);});
    const auto other=encrypt(sequence(1024,1),key);fails([&]{decrypt(c.ciphertext,key,other.sidecar);});
}
void embedded_tamper() {
    Options options;options.layout=Layout::embedded;const auto c=encrypt(sequence(1024),key,options);
    auto bad=c.ciphertext;
    const auto j=std::find_if(bad.begin()+1,bad.end(),[&](Byte x){return x!=bad[0];});
    std::iter_swap(bad.begin(),j);CHECK(histogram(bad)==histogram(c.ciphertext));fails([&]{decrypt(bad,key);});
    auto h=histogram(c.ciphertext);const auto rank=rank_bytes(c.ciphertext,h);--h[0];++h[1];
    CHECK(rank<multinomial(h));const auto changed=unrank_bytes(rank,h);fails([&]{decrypt(changed,key);});
    fails([&]{decrypt({},key);});
}
void authenticated_overflow() {
    auto c=detail::encrypt_with_nonce(sequence(256),key,Options{},nonce);
    const auto keys=detail::derive_keys(key,nonce,2,Layout::detached);
    const View header=View(*c.sidecar).first(header_size);
    const auto aad=detail::concat({header,c.ciphertext});
    auto priv=detail::aes_gcm_decrypt(keys[1],View(nonce).subspan(12,12),View(*c.sidecar).subspan(header_size),aad);
    std::fill(priv.begin(),priv.begin()+8,0xff);
    const auto meta=detail::aes_gcm_encrypt(keys[1],View(nonce).subspan(12,12),priv,aad);
    const auto invalid=detail::concat({header,meta});fails([&]{decrypt(c.ciphertext,key,invalid);});
}
void malformed_inputs() {
    std::mt19937 rng(9831);
    for(int i=0;i<100;++i) {
        Bytes data(static_cast<std::size_t>(rng()%128));for(auto& b:data)b=static_cast<Byte>(rng());
        fails([&]{decrypt(data,key);});
        Bytes sidecar(sidecar_size);for(auto& b:sidecar)b=static_cast<Byte>(rng());
        fails([&]{decrypt(data,key,sidecar);});
    }
}
void crypto_primitives() {
    CHECK(hex(sha256(Bytes{'a','b','c'}))=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const auto c=detail::aes_gcm_encrypt(Bytes(32),Bytes(12),Bytes(16),{});
    CHECK(hex(c)=="cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
    CHECK(detail::aes_gcm_decrypt(Bytes(32),Bytes(12),c,{})==Bytes(16));
    auto bad=c;bad.back()^=1;fails([&]{detail::aes_gcm_decrypt(Bytes(32),Bytes(12),bad,{});});
    const auto empty=detail::aes_gcm_encrypt(key,Bytes(12),{},{});
    CHECK(detail::aes_gcm_decrypt(key,Bytes(12),empty,{}).empty());
}
void file_io() {
    const auto dir=std::filesystem::temp_directory_path()/("0xbof-test-"+hex(random_bytes(12)));
    std::filesystem::create_directories(dir);
    try {
        const auto a=dir/"a",b=dir/"b";
        atomic_write(a,sequence(32));CHECK(read_limited(a,32)==sequence(32));
        fails([&]{atomic_write(a,Bytes(32));});CHECK(read_limited(a,32)==sequence(32));
        fails([&]{read_limited(a,31);});fails([&]{ensure_distinct({a,a});});
        std::filesystem::create_hard_link(a,b);fails([&]{ensure_distinct({a,b});});
        std::filesystem::remove(b);atomic_write(a,Bytes(32),true);CHECK(read_limited(a,32)==Bytes(32));
        atomic_write(b,{});CHECK(read_limited(b,0).empty());
        ensure_distinct({a,b});
    } catch (...) {std::filesystem::remove_all(dir);throw;}
    std::filesystem::remove_all(dir);
}
}
int main() {
    const std::vector<std::pair<const char*,std::function<void()>>> tests{
        {"exhaustive 1093 ranks",exhaustive},{"80 random ranks",random_enumeration},{"invalid ranks and count overflow",invalid_ranks},
        {"modular spill reconstruction",spills},{"budget shapes and capacity",policies},{"exact histogram certificate",exact_policy},
        {"exact decimal budget parsing",budgets},{"PE32/PE32+ validation",pe_validation},{"resource limits",resources},
        {"zero embedded capacity",zero_capacity},{"two profiles and two layouts",all_profiles_layouts},{"random detached roundtrips",random_roundtrips},
        {"constant inputs",constant_inputs},{"fresh nonces",nonce_freshness},{"ECLAB001 known-answer vectors",regression_vectors},
        {"wrong key authentication",wrong_keys},{"detached tamper and sidecar swap",tamper},{"embedded tamper and histogram binding",embedded_tamper},
        {"authenticated malicious histogram",authenticated_overflow},{"200 malformed artifacts",malformed_inputs},
        {"SHA-256 and AES-GCM vectors",crypto_primitives},{"atomic file IO and aliases",file_io}};
    int failures=0;
    const auto start=std::chrono::steady_clock::now();
    for(const auto& [name,function]:tests) {
        try {function();std::cout<<"PASS "<<name<<std::endl;}
        catch(const std::exception& error){++failures;std::cerr<<"FAIL "<<name<<": "<<error.what()<<std::endl;}
    }
    std::cout<<Json{{"test_groups",tests.size()},{"failures",failures},{"exhaustive_rank_cases",1093},{"random_rank_cases",80},
        {"elapsed_seconds",std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count()}}.dump(2)<<'\n';
    return failures?1:0;
}
