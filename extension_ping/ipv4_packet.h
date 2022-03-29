#pragma once

#include <algorithm>
#include <sstream>
#include <boost/asio/ip/address_v4.hpp>


class ipv4_header
{
public:

    //Start offset for different fields
    static const unsigned short OFFSET_FIELD_VERSION_AND_HEADER = 0;
    static const unsigned short OFFSET_FIELD_TYPE_OF_SERVICE = 1;
    static const unsigned short OFFSET_FIELD_TOTAL_LENGTH_START = 2;
    static const unsigned short OFFSET_FIELD_TOTAL_LENGTH_END = 3;
    static const unsigned short OFFSET_FIELD_IDENTIFICATION_START = 4;
    static const unsigned short OFFSET_FIELD_IDENTIFICATION_END = 5;
    static const unsigned short OFFSET_FIELD_FRAGMENT_START = 6;
    static const unsigned short OFFSET_FIELD_FRAGMENT_END = 7;
    static const unsigned short OFFSET_FIELD_TIME_TO_LIVE = 8;
    static const unsigned short OFFSET_FIELD_PROTOCOL = 9;
    static const unsigned short OFFSET_FIELD_HEADER_CHECKSUM_START = 10;
    static const unsigned short OFFSET_FIELD_HEADER_CHECKSUM_END = 11;
    static const unsigned short OFFSET_FIELD_SOURCE_ADDRESS_OCTET_1 = 12;
    static const unsigned short OFFSET_FIELD_SOURCE_ADDRESS_OCTET_2 = 13;
    static const unsigned short OFFSET_FIELD_SOURCE_ADDRESS_OCTET_3 = 14;
    static const unsigned short OFFSET_FIELD_SOURCE_ADDRESS_OCTET_4 = 15;
    static const unsigned short OFFSET_FIELD_TARGET_ADDRESS_OCTET_1 = 16;
    static const unsigned short OFFSET_FIELD_TARGET_ADDRESS_OCTET_2 = 17;
    static const unsigned short OFFSET_FIELD_TARGET_ADDRESS_OCTET_3 = 18;
    static const unsigned short OFFSET_FIELD_TARGET_ADDRESS_OCTET_4 = 19;

    //Some magic data
    static const unsigned short MAX_PACKET_SIZE = 65535;
    static const unsigned short MAX_IDENTIFIER_POSSIBLE = 65535;
    static const unsigned short IPV4_PACKET_SIZE_IN_BYTES = 60;
    static const unsigned short IPV4_HEADER_SIZE_IN_BYTES = 20;
    static const unsigned short IPV4_VERSION = 4;

    //Lifecycle management
    ipv4_header() { clear(); }

    //Getters
    unsigned char version() const { return (packet_buffer[OFFSET_FIELD_VERSION_AND_HEADER] >> 4) & 0xF; }
    unsigned short header_length() const { return (packet_buffer[OFFSET_FIELD_VERSION_AND_HEADER] & 0xF) * 4; }
    unsigned char type_of_service() const { return packet_buffer[OFFSET_FIELD_TYPE_OF_SERVICE]; }
    unsigned short total_length() const { return get_short_from_offsets(OFFSET_FIELD_TOTAL_LENGTH_START, OFFSET_FIELD_TOTAL_LENGTH_END); }
    unsigned short identification() const { return get_short_from_offsets(OFFSET_FIELD_IDENTIFICATION_START, OFFSET_FIELD_IDENTIFICATION_END); }
    bool dont_fragment() const { return (packet_buffer[OFFSET_FIELD_FRAGMENT_START] & 0x40) != 0; }
    bool more_fragments() const { return (packet_buffer[OFFSET_FIELD_FRAGMENT_START] & 0x20) != 0; }
    unsigned short fragment_offset() const { return get_short_from_offsets(OFFSET_FIELD_FRAGMENT_START, OFFSET_FIELD_FRAGMENT_END) & 0x1FFF; }
    unsigned int time_to_live() const { return packet_buffer[OFFSET_FIELD_TIME_TO_LIVE]; }
    unsigned char protocol() const { return packet_buffer[OFFSET_FIELD_PROTOCOL]; }
    unsigned short header_checksum() const { return get_short_from_offsets(OFFSET_FIELD_HEADER_CHECKSUM_START, IPV4_HEADER_SIZE_IN_BYTES); }
    boost::asio::ip::address_v4 source_address() const;
    boost::asio::ip::address_v4 destination_address() const;

    //Helpers
    void clear();
    bool is_ready() const;

    friend std::istream& operator>>(std::istream& input_stream, ipv4_header& header)
    {
        input_stream.read(reinterpret_cast<char*>(header.packet_buffer), IPV4_HEADER_SIZE_IN_BYTES);
        if (header.version() != 4)
        {
            input_stream.setstate(std::ios::failbit);
        }
            
        //check if we can medir la radio
        std::streamsize options_length = header.header_length() - IPV4_HEADER_SIZE_IN_BYTES;
        if ((options_length < 0) ||
            (options_length > 40))
        {
            input_stream.setstate(std::ios::failbit);
        }            
        else
        {
            input_stream.read(reinterpret_cast<char*>(header.packet_buffer) + IPV4_HEADER_SIZE_IN_BYTES, options_length);
        }
            
        return input_stream;
    }

private:
    unsigned short get_short_from_offsets(const unsigned short offset_1, const unsigned short offset_2) const;

    unsigned char packet_buffer[IPV4_PACKET_SIZE_IN_BYTES];
};