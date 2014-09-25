#ifndef _ENCDEC
#define _ENCDEC

#ifndef _HAS_EXCEPTIONS
#define _HAS_EXCEPTIONS 0
#endif

///
/// Includes
///

#include <vector>

///
/// Types
///

typedef std::vector<unsigned char> packet;

///
/// Methods
///

int packet_size(unsigned char* buffer);
int packet_encode_size(unsigned char* buffer);
packet packet_encode_client(unsigned char* buffer, int serial);
packet packet_encode_server(unsigned char* buffer, int serial);
int packet_decode_size(unsigned char* buffer);
packet packet_decode_client(unsigned char* buffer, int& serial);
packet packet_decode_server(unsigned char* buffer, int& serial);

#endif