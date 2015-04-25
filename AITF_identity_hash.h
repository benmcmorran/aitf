#pragma once

#include <functional>

#include "AITF_identity.h"
#include "RRFilter.h"

namespace std
{
    template<>
    struct hash<AITF_identity>
    { 
        std::size_t operator()(AITF_identity const& val) const
        {
        	std::size_t const h1 ( std::hash<uint32_t>()((uint32_t)val.victim()) );
            //std::size_t const h2 ( std::hash<std::vector<RRFilter>>()(val.filters()) );
            std::size_t const h3 ( std::hash<int>()(val.pointer()) );
            return h1 ^ (h3 << 1);//(h2 << 1) ^ (h3 << 2);
        }
    };

    template<>
    struct hash<RRFilter>
    {
        std::size_t operator()(RRFilter const& val) const
        {
            std::size_t const h1 ( std::hash<uint8_t>() (val.match_type()));
            std::size_t const h2 ( std::hash<uint32_t>()((uint32_t)val.address()));
            std::size_t const h3 ( std::hash<uint64_t>() (val.random_number_1()));
            std::size_t const h4 ( std::hash<uint64_t>() (val.random_number_2()));
            return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
        }
    };
}