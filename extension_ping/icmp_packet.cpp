#include "icmp_packet.h"

//Internet Checksum implementation as detailed in https://datatracker.ietf.org/doc/html/rfc1071#section-4
bool icmp_header::update_checksum(std::string payload)
{
    bool ret = false;

    if (!payload.empty())
    {
        unsigned int work_checksum_data =
            (type() << 8) +
            code() +
            identifier() +
            sequence_number();

        //Traverse payload bytes
        std::string::iterator it = payload.begin();
        while (it != payload.end())
        {
            work_checksum_data += (static_cast<unsigned char>(*it++) << 8);
            if (it != payload.end())
            {
                work_checksum_data += static_cast<unsigned char>(*it++);
            }                
        }

        work_checksum_data = (work_checksum_data >> 16) + (work_checksum_data & 0xFFFF);
        work_checksum_data += (work_checksum_data >> 16);

        //Update Checksum
        checksum(static_cast<unsigned short>(~work_checksum_data));

        ret = true;
    }

    return true;
}

//Clean internal packet buffer
void icmp_header::clear()
{
    std::fill(packet_buffer, packet_buffer + sizeof(packet_buffer), 0);
}

bool icmp_header::is_ready() const
{
    bool ret = false;

    //just doing a naive check to look for ICMP Echo Request/Reply packets
    if ((code() == icmp_header::ICMP_HEADER_CODE_TYPE::ECHO_REQUEST) ||
        (code() == icmp_header::ICMP_HEADER_CODE_TYPE::ECHO_REPLY))
    {
        ret = true;
    }

    return ret;
}

//short-to-network helper
unsigned short icmp_header::get_short_from_offsets(const unsigned short offset_1, const unsigned short offset_2) const
{
    return (packet_buffer[offset_1] << 8) + packet_buffer[offset_2];
}

//network-to-short helper
void icmp_header::save_short_into_offsets(const unsigned short offset_1, const unsigned short offset_2, const unsigned short value) 
{
    packet_buffer[offset_1] = static_cast<unsigned char>(value >> 8);
    packet_buffer[offset_2] = static_cast<unsigned char>(value & 0xFF);
}

