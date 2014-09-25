#ifndef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#endif

///
/// Warnings
///

#ifdef __WIN32
#pragma warning(disable: 4530, 4267, 4506, 4230, 4506)
#endif

///
/// Includes
///

#include <vector>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include "encdec.h"


///
/// Namespaces
///

using namespace v8;
using namespace node;

///
/// Macros
///

#define V8_CHECK_ARGUMENT_COUNT(n) \
    HandleScope scope; \
    if (args.Length() < n) { \
        return ThrowException(Exception::TypeError(String::New("This function receives " #n " parameters."))); \
    }

#define V8_CHECK_ARGUMENT(n, method) \
    if (!args[n]->Is##method##()) { \
        return ThrowException(Exception::TypeError(String::New("Argument " #n " must be " #method))); \
    }

///
/// Methods
///

Handle<Value> node_packet_size(const Arguments& args)
{
    V8_CHECK_ARGUMENT_COUNT(1)
    V8_CHECK_ARGUMENT(0, Object)

    Local<Object> buffer = args[0]->ToObject();
    unsigned char* buffer_ptr = (unsigned char*) node::Buffer::Data(buffer);

    int size = packet_size(buffer_ptr);
    return scope.Close(Integer::New(size));
}

Handle<Value> node_packet_encode_size(const Arguments& args)
{
    V8_CHECK_ARGUMENT_COUNT(1)
    V8_CHECK_ARGUMENT(0, Object)

    Local<Object> buffer = args[0]->ToObject();
    unsigned char* buffer_ptr = (unsigned char*) node::Buffer::Data(buffer);

    int size = packet_encode_size(buffer_ptr);
    return scope.Close(Integer::New(size));
}

Handle<Value> node_packet_decode_size(const Arguments& args)
{
    V8_CHECK_ARGUMENT_COUNT(1)
    V8_CHECK_ARGUMENT(0, Object)

    Local<Object> buffer = args[0]->ToObject();
    unsigned char* buffer_ptr = (unsigned char*) node::Buffer::Data(buffer);

    int size = packet_decode_size(buffer_ptr);
    return scope.Close(Integer::New(size));
}

///
/// Encoders
///

Handle<Value> node_packet_client_encode(const Arguments& args)
{
    V8_CHECK_ARGUMENT_COUNT(2)
    V8_CHECK_ARGUMENT(0, Object)
    V8_CHECK_ARGUMENT(1, Number)

    Local<Object> buffer = args[0]->ToObject();
    int32_t serial = args[1]->Int32Value();
    unsigned char* buffer_ptr = (unsigned char*) node::Buffer::Data(buffer);
    int length = (int) node::Buffer::Length(buffer);

    packet pkt = packet_encode_client(buffer_ptr, serial);
    if (pkt.empty())
    {
        return scope.Close(Null());
    }

    int s = (int) pkt.size();
    Local<Object> globalObj = Context::GetCurrent()->Global();
    Local<Function> bufferConstructor = Local<Function>::Cast(globalObj->Get(String::New("Buffer")));
    Handle<Value> constructorArgs[1] = { v8::Integer::New(s)};
    Local<Object> actualBuffer = bufferConstructor->NewInstance(1, constructorArgs);
    memcpy(Buffer::Data(actualBuffer), pkt.data(), s);
    return scope.Close(actualBuffer);
}

Handle<Value> node_packet_server_encode(const Arguments& args)
{
    V8_CHECK_ARGUMENT_COUNT(2)
    V8_CHECK_ARGUMENT(0, Object)
    V8_CHECK_ARGUMENT(1, Number)

    Local<Object> buffer = args[0]->ToObject();
    int32_t serial = args[1]->Int32Value();
    unsigned char* buffer_ptr = (unsigned char*) node::Buffer::Data(buffer);
    int length = (int) node::Buffer::Length(buffer);

    packet pkt = packet_encode_server(buffer_ptr, serial);
    if (pkt.empty())
    {
        return scope.Close(Null());
    }

    int s = (int) pkt.size();
    Local<Object> globalObj = Context::GetCurrent()->Global();
    Local<Function> bufferConstructor = Local<Function>::Cast(globalObj->Get(String::New("Buffer")));
    Handle<Value> constructorArgs[1] = { v8::Integer::New(s)};
    Local<Object> actualBuffer = bufferConstructor->NewInstance(1, constructorArgs);
    memcpy(Buffer::Data(actualBuffer), pkt.data(), s);
    return scope.Close(actualBuffer);
}

///
/// Decoders
///

Handle<Value> node_packet_client_decode(const Arguments& args)
{
    V8_CHECK_ARGUMENT_COUNT(1)
    V8_CHECK_ARGUMENT(0, Object)

    Local<Object> buffer = args[0]->ToObject();
    unsigned char* buffer_ptr = (unsigned char*) node::Buffer::Data(buffer);
    int length = (int) node::Buffer::Length(buffer);

    int serial = -1;
    packet pkt = packet_decode_client(buffer_ptr, serial);
    if (pkt.empty())
    {
        return scope.Close(Null());
    }

    int s = (int) pkt.size();
    Local<Object> globalObj = Context::GetCurrent()->Global();
    Local<Function> bufferConstructor = Local<Function>::Cast(globalObj->Get(String::New("Buffer")));
    Handle<Value> constructorArgs[1] = { v8::Integer::New(s)};
    Local<Object> actualBuffer = bufferConstructor->NewInstance(1, constructorArgs);
    memcpy(Buffer::Data(actualBuffer), pkt.data(), s);

    Local<Object> ret = Object::New();
    ret->Set(String::New("serial"), Integer::New(serial));
    ret->Set(String::New("buffer"), actualBuffer);

    return scope.Close(ret);
}

Handle<Value> node_packet_server_decode(const Arguments& args)
{
    V8_CHECK_ARGUMENT_COUNT(1)
    V8_CHECK_ARGUMENT(0, Object)

    Local<Object> buffer = args[0]->ToObject();
    unsigned char* buffer_ptr = (unsigned char*) node::Buffer::Data(buffer);
    int length = (int) node::Buffer::Length(buffer);

    int serial = -1;
    packet pkt = packet_decode_server(buffer_ptr, serial);
    if (pkt.empty())
    {
        return scope.Close(Null());
    }

    int s = (int) pkt.size();
    Local<Object> globalObj = Context::GetCurrent()->Global();
    Local<Function> bufferConstructor = Local<Function>::Cast(globalObj->Get(String::New("Buffer")));
    Handle<Value> constructorArgs[1] = { v8::Integer::New(s) };
    Local<Object> actualBuffer = bufferConstructor->NewInstance(1, constructorArgs);
    memcpy(Buffer::Data(actualBuffer), pkt.data(), s);

    Local<Object> ret = Object::New();
    ret->Set(String::New("serial"), Integer::New(serial));
    ret->Set(String::New("buffer"), actualBuffer);

    return scope.Close(ret);
}

///
/// Module register
///

void RegisterModule(v8::Handle<v8::Object> target)
{
    NODE_SET_METHOD(target, "get_size", node_packet_size);
    NODE_SET_METHOD(target, "get_encoded_size", node_packet_encode_size);
    NODE_SET_METHOD(target, "get_decoded_size", node_packet_decode_size);
    NODE_SET_METHOD(target, "client_encode", node_packet_client_encode);
    NODE_SET_METHOD(target, "client_decode", node_packet_server_decode);
    NODE_SET_METHOD(target, "server_encode", node_packet_server_encode);
    NODE_SET_METHOD(target, "server_decode", node_packet_client_decode);
}

///
/// Node module
///

NODE_MODULE(munet, RegisterModule);