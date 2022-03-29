#pragma once

#include <istream>
#include <ostream>
#include <algorithm>

class icmp_header
{
public:
    typedef enum
    {
        ECHO_REPLY = 0,
        DEST_UNREACHABLE = 3,
        SOURCE_QUENCH = 4,
        REDIRECT = 5,
        ALTERNATE_HOST_ADDRESS = 5,
        ECHO_REQUEST = 8,
        ROUTER_ADVERTISEMENT = 8,
        TIME_EXCEEDED = 11,
        PARAMETER_PROBLEM = 12,
        TIMESTAMP_REQUEST = 13,
        TIMESTAMP_REPLY = 14,
        INFORMATION_REQUEST = 15,
        INFORMATION_REPLY = 16,
        ADDRESS_MASK_REQUEST = 17,
        ADDRESS_MASK_REPLY = 18,
        TRACEROUTE = 30,
        NA
    } ICMP_HEADER_CODE_TYPE;

    //Start offset for different fields
    static const unsigned short OFFSET_FIELD_TYPE = 0;
    static const unsigned short OFFSET_FIELD_CODE = 1;
    static const unsigned short OFFSET_FIELD_CHECKSUM_START = 2;
    static const unsigned short OFFSET_FIELD_CHECKSUM_END = 3;
    static const unsigned short OFFSET_FIELD_IDENTIFIER_START = 4;
    static const unsigned short OFFSET_FIELD_IDENTIFIER_END = 5;
    static const unsigned short OFFSET_FIELD_SEQUENCE_NUMBER_START = 6;
    static const unsigned short OFFSET_FIELD_SEQUENCE_NUMBER_END = 7;

    //Some magic data
    static const unsigned short ICMP_PACKET_SIZE_IN_BYTES = 8;

    //Lifecycle management
    icmp_header() { clear(); }

    //Getters
    unsigned char type() const { return packet_buffer[OFFSET_FIELD_TYPE]; }
    unsigned char code() const { return packet_buffer[OFFSET_FIELD_CODE]; }
    unsigned short checksum() const { return get_short_from_offsets(OFFSET_FIELD_CHECKSUM_START, OFFSET_FIELD_CHECKSUM_END); }
    unsigned short identifier() const { return get_short_from_offsets(OFFSET_FIELD_IDENTIFIER_START, OFFSET_FIELD_IDENTIFIER_END); }
    unsigned short sequence_number() const { return get_short_from_offsets(OFFSET_FIELD_SEQUENCE_NUMBER_START, OFFSET_FIELD_SEQUENCE_NUMBER_END); }

    //setters
    void type(unsigned char value) { packet_buffer[OFFSET_FIELD_TYPE] = value; }
    void code(unsigned char value) { packet_buffer[OFFSET_FIELD_CODE] = value; }
    void checksum(unsigned short value) { save_short_into_offsets(OFFSET_FIELD_CHECKSUM_START, OFFSET_FIELD_CHECKSUM_END, value); }
    void identifier(unsigned short value) { save_short_into_offsets(OFFSET_FIELD_IDENTIFIER_START, OFFSET_FIELD_IDENTIFIER_END, value); }
    void sequence_number(unsigned short value) { save_short_into_offsets(OFFSET_FIELD_SEQUENCE_NUMBER_START, OFFSET_FIELD_SEQUENCE_NUMBER_END, value); }

    //Helpers
    void clear();
    bool is_ready() const;
    bool update_checksum(std::string payload);


    friend std::istream& operator>>(std::istream& is, icmp_header& header)
    {
        return is.read(reinterpret_cast<char*>(header.packet_buffer), ICMP_PACKET_SIZE_IN_BYTES);
    }

    friend std::ostream& operator<<(std::ostream& os, const icmp_header& header)
    {
        return os.write(reinterpret_cast<const char*>(header.packet_buffer), ICMP_PACKET_SIZE_IN_BYTES);
    }

private:
    //Network-to-short and short-to-network helpers
    unsigned short get_short_from_offsets(const unsigned short offset_1, const unsigned short offset_2) const;
    void save_short_into_offsets(const unsigned short offset_1, const unsigned short offset_2, const unsigned short value);

    unsigned char packet_buffer[ICMP_PACKET_SIZE_IN_BYTES];
};



