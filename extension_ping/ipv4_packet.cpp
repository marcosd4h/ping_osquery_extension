#include "ipv4_packet.h"

//Clean internal packet buffer
void ipv4_header::clear()
{
	std::fill(packet_buffer, packet_buffer + sizeof(packet_buffer), 0);
}

//check that packet is ready for usage
bool ipv4_header::is_ready() const
{
    bool ret = false;

    //just doing a naive check to look for specific IPV4 header
    if (version() == IPV4_VERSION)
    {
        ret = true;
    }

    return ret;
}

//gather source address in boost form
boost::asio::ip::address_v4 ipv4_header::source_address() const
{
    boost::asio::ip::address_v4::bytes_type bytes  = { 
        { 
            packet_buffer[OFFSET_FIELD_SOURCE_ADDRESS_OCTET_1], 
            packet_buffer[OFFSET_FIELD_SOURCE_ADDRESS_OCTET_2], 
            packet_buffer[OFFSET_FIELD_SOURCE_ADDRESS_OCTET_3], 
            packet_buffer[OFFSET_FIELD_SOURCE_ADDRESS_OCTET_4] 
        } 
    };

    return boost::asio::ip::address_v4(bytes);
}

//gather destination address in boost form
boost::asio::ip::address_v4 ipv4_header::destination_address() const
{
    boost::asio::ip::address_v4::bytes_type bytes = 
    { 
        { 
            packet_buffer[OFFSET_FIELD_TARGET_ADDRESS_OCTET_1],
            packet_buffer[OFFSET_FIELD_TARGET_ADDRESS_OCTET_2],
            packet_buffer[OFFSET_FIELD_TARGET_ADDRESS_OCTET_3],
            packet_buffer[OFFSET_FIELD_TARGET_ADDRESS_OCTET_4]
        } 
    };
    return boost::asio::ip::address_v4(bytes);
}

//short-from-network helpers
unsigned short ipv4_header::get_short_from_offsets(const unsigned short offset_1, const unsigned short offset_2) const
{
    return (packet_buffer[offset_1] << 8) + packet_buffer[offset_2];
}