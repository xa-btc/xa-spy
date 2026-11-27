#pragma once
#include <charconv>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

// Small bounded JSON data parser; no schema callbacks, evaluation or extension hooks.
namespace xa::json {
struct Value {
    enum class Type { null, boolean, number, string, array, object } type = Type::null;
    std::string text;
    std::vector<Value> items;
    std::map<std::string, Value> members;
    const Value& at(const std::string& key) const {
        if (type != Type::object) throw std::runtime_error("JSON object required");
        return members.at(key);
    }
    std::uint64_t uint() const {
        if (type != Type::number || text.empty()) throw std::runtime_error("JSON integer required");
        std::uint64_t out = 0;
        auto result = std::from_chars(text.data(), text.data() + text.size(), out);
        if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) throw std::runtime_error("JSON integer invalid");
        return out;
    }
    const std::string& string() const {
        if (type != Type::string) throw std::runtime_error("JSON string required");
        return text;
    }
};
class Parser {
    const std::string& input;
    size_t pos = 0, nodes = 0;
    [[noreturn]] void fail() const { throw std::runtime_error("invalid or excessive JSON"); }
    void space() { while (pos < input.size() && (input[pos]==' ' || input[pos]=='\r' || input[pos]=='\n' || input[pos]=='\t')) ++pos; }
    bool eat(char c) { space(); if (pos < input.size() && input[pos] == c) { ++pos; return true; } return false; }
    unsigned hex4() {
        unsigned value = 0;
        for (int i=0;i<4;++i) {
            if (pos == input.size()) fail();
            char c = input[pos++]; unsigned digit;
            if(c>='0'&&c<='9') digit=c-'0'; else if(c>='A'&&c<='F') digit=c-'A'+10;
            else if(c>='a'&&c<='f') digit=c-'a'+10; else fail();
            value=value*16+digit;
        }
        return value;
    }
    void utf8(std::string& s, unsigned c) {
        if(c<128) s+=static_cast<char>(c);
        else if(c<2048) {s+=static_cast<char>(0xc0|(c>>6));s+=static_cast<char>(0x80|(c&63));}
        else if(c<65536) {s+=static_cast<char>(0xe0|(c>>12));s+=static_cast<char>(0x80|((c>>6)&63));s+=static_cast<char>(0x80|(c&63));}
        else {s+=static_cast<char>(0xf0|(c>>18));s+=static_cast<char>(0x80|((c>>12)&63));s+=static_cast<char>(0x80|((c>>6)&63));s+=static_cast<char>(0x80|(c&63));}
    }
    std::string string() {
        if (!eat('"')) fail(); std::string s;
        while (pos < input.size()) {
            unsigned char c=input[pos++];
            if(c=='"') return s;
            if(c<32 || s.size()>131072) fail();
            if(c!='\\') {s+=static_cast<char>(c);continue;}
            if(pos==input.size()) fail();
            switch(input[pos++]) {
            case '"':s+='"';break;case '\\':s+='\\';break;case '/':s+='/';break;
            case 'b':s+='\b';break;case 'f':s+='\f';break;case 'n':s+='\n';break;case 'r':s+='\r';break;case 't':s+='\t';break;
            case 'u': {auto cp=hex4();if(cp>=0xd800&&cp<=0xdbff){
                if(pos+2>input.size()||input[pos++]!='\\'||input[pos++]!='u')fail();
                auto low=hex4();if(low<0xdc00||low>0xdfff)fail();cp=0x10000+((cp-0xd800)<<10)+(low-0xdc00);
            } else if(cp>=0xdc00&&cp<=0xdfff)fail();utf8(s,cp);break;}
            default:fail();
            }
        } fail();
    }
    Value value(unsigned depth) {
        if(depth>32||++nodes>200000)fail();space(); if(pos==input.size())fail();Value v;
        if(input[pos]=='"'){v.type=Value::Type::string;v.text=string();return v;}
        if(eat('{')) {v.type=Value::Type::object;if(eat('}'))return v;do{
            auto key=string();if(!eat(':')||v.members.contains(key))fail();v.members.emplace(key,value(depth+1));
        }while(eat(','));if(!eat('}'))fail();return v;}
        if(eat('[')){v.type=Value::Type::array;if(eat(']'))return v;do{v.items.push_back(value(depth+1));}while(eat(','));if(!eat(']'))fail();return v;}
        for(const auto* literal:{"null","true","false"}){const std::string token(literal);if(input.compare(pos,token.size(),token)==0){pos+=token.size();v.type=token=="null"?Value::Type::null:Value::Type::boolean;v.text=token;return v;}}
        auto start=pos;if(input[pos]=='-')++pos;
        if(pos==input.size()||input[pos]<'0'||input[pos]>'9')fail();
        if(input[pos]=='0')++pos;else while(pos<input.size()&&input[pos]>='0'&&input[pos]<='9')++pos;
        if(pos<input.size()&&input[pos]=='.'){++pos;auto first=pos;while(pos<input.size()&&input[pos]>='0'&&input[pos]<='9')++pos;if(first==pos)fail();}
        if(pos<input.size()&&(input[pos]=='e'||input[pos]=='E')){++pos;if(pos<input.size()&&(input[pos]=='+'||input[pos]=='-'))++pos;auto first=pos;while(pos<input.size()&&input[pos]>='0'&&input[pos]<='9')++pos;if(first==pos)fail();}
        v.type=Value::Type::number;v.text=input.substr(start,pos-start);return v;
    }
public:
    explicit Parser(const std::string& data):input(data){if(data.size()>8*1024*1024)fail();}
    Value parse(){auto v=value(0);space();if(pos!=input.size())fail();return v;}
};
inline Value parse(const std::string& data){return Parser(data).parse();}
}
